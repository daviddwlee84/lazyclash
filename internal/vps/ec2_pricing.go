package vps

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// AWS CLI automatic pagination is deliberately disabled: absence and pricing
// are accepted only after every API page has been decoded and checked.
func (s *Service) ec2Rows(ctx context.Context, req CreateRequest, key string, args ...string) ([]map[string]any, error) {
	var result []map[string]any
	seen := map[string]bool{}
	token := ""
	for page := 0; page < 1000; page++ {
		a := append(append([]string(nil), args...), "--no-paginate")
		if token != "" {
			a = append(a, "--next-token", token)
		}
		v, err := s.call(ctx, req, a...)
		if err != nil {
			return nil, err
		}
		rows, err := strictItems(v, key)
		if err != nil {
			return nil, err
		}
		result = append(result, rows...)
		if raw, ok := obj(v)["NextToken"]; ok && raw != nil {
			var valid bool
			token, valid = raw.(string)
			if !valid {
				return nil, fmt.Errorf("AWS %s pagination token is malformed", key)
			}
		} else {
			token = ""
		}
		if token == "" {
			return result, nil
		}
		if seen[token] {
			return nil, fmt.Errorf("AWS %s repeated a pagination token", key)
		}
		seen[token] = true
	}
	return nil, fmt.Errorf("AWS %s pagination exceeds safety bound", key)
}

func ec2Filter(field, value string) map[string]string {
	return map[string]string{"Type": "TERM_MATCH", "Field": field, "Value": value}
}

func (s *Service) ec2Prices(ctx context.Context, req CreateRequest, service string, filters ...map[string]string) ([]map[string]any, error) {
	// The Pricing Query API endpoint is independent of the VM's region.
	pricing := req
	pricing.Region = "us-east-1"
	var products []map[string]any
	token := ""
	seen := map[string]bool{}
	for page := 0; page < 1000; page++ {
		args := []string{"pricing", "get-products", "--service-code", service, "--format-version", "aws_v1", "--filters", jsonValue(filters), "--max-results", "100", "--no-paginate"}
		if token != "" {
			args = append(args, "--next-token", token)
		}
		v, err := s.call(ctx, pricing, args...)
		if err != nil {
			return nil, err
		}
		list, ok := obj(v)["PriceList"].([]any)
		if !ok {
			return nil, fmt.Errorf("AWS Pricing response lacks PriceList")
		}
		for _, raw := range list {
			encoded, ok := raw.(string)
			if !ok {
				return nil, fmt.Errorf("AWS Pricing product is not encoded JSON")
			}
			var p map[string]any
			if err = json.Unmarshal([]byte(encoded), &p); err != nil {
				return nil, fmt.Errorf("AWS Pricing product is malformed")
			}
			if str(obj(p["product"])["sku"]) == "" {
				return nil, fmt.Errorf("AWS Pricing product lacks SKU")
			}
			attrs := obj(obj(p["product"])["attributes"])
			for _, f := range filters {
				if str(attrs[f["Field"]]) != f["Value"] {
					return nil, fmt.Errorf("AWS Pricing returned an unexpected %s product", service)
				}
			}
			products = append(products, p)
		}
		token = ""
		if raw, ok := obj(v)["NextToken"]; ok && raw != nil {
			var valid bool
			token, valid = raw.(string)
			if !valid {
				return nil, fmt.Errorf("AWS Pricing token is malformed")
			}
		}
		if token == "" {
			return products, nil
		}
		if seen[token] {
			return nil, fmt.Errorf("AWS Pricing repeated a pagination token")
		}
		seen[token] = true
	}
	return nil, fmt.Errorf("AWS Pricing pagination exceeds safety bound")
}

type ec2PriceDimension struct {
	Begin, End, USD float64
	Unit            string
}

func ec2Dimensions(products []map[string]any) ([]ec2PriceDimension, error) {
	var result []ec2PriceDimension
	for _, p := range products {
		terms := obj(obj(p["terms"])["OnDemand"])
		if len(terms) != 1 {
			return nil, fmt.Errorf("AWS Pricing requires one current on-demand term per product")
		}
		for _, raw := range terms {
			term := obj(raw)
			if len(obj(term["termAttributes"])) != 0 {
				return nil, fmt.Errorf("AWS Pricing restricted on-demand terms are not a per-VM price")
			}
			dims := obj(term["priceDimensions"])
			if len(dims) == 0 {
				return nil, fmt.Errorf("AWS Pricing lacks dimensions")
			}
			for _, r := range dims {
				m := obj(r)
				if len(arr(m["appliesTo"])) != 0 {
					return nil, fmt.Errorf("AWS Pricing shared allowances cannot be deducted from this VM")
				}
				begin, e1 := strconv.ParseFloat(str(m["beginRange"]), 64)
				end, e2 := strconv.ParseFloat(str(m["endRange"]), 64)
				usd, e3 := strconv.ParseFloat(str(obj(m["pricePerUnit"])["USD"]), 64)
				if e1 != nil || e2 != nil || e3 != nil || math.IsNaN(begin) || math.IsInf(begin, 0) || begin < 0 || math.IsNaN(end) || end <= begin || math.IsNaN(usd) || math.IsInf(usd, 0) || usd < 0 {
					return nil, fmt.Errorf("AWS Pricing has an invalid range or USD price")
				}
				result = append(result, ec2PriceDimension{Begin: begin, End: end, USD: usd, Unit: str(m["unit"])})
			}
		}
	}
	return result, nil
}
func ec2FixedRate(products []map[string]any, unit string) (float64, error) {
	if len(products) != 1 {
		return 0, fmt.Errorf("AWS Pricing found %d matching products; expected one", len(products))
	}
	dims, err := ec2Dimensions(products)
	if err != nil {
		return 0, err
	}
	if len(dims) != 1 || dims[0].Unit != unit || dims[0].Begin != 0 || !math.IsInf(dims[0].End, 1) || dims[0].USD <= 0 {
		return 0, fmt.Errorf("AWS Pricing did not return one positive %s rate", unit)
	}
	return dims[0].USD, nil
}

type ec2CostFacts struct {
	Compute, Disk, IPv4, IdleIPv4 float64
	Transfer                      []ec2PriceDimension
}

func (s *Service) ec2Cost(ctx context.Context, req CreateRequest, diskGB int) (ec2CostFacts, error) {
	var c ec2CostFacts
	products, err := s.ec2Prices(ctx, req, "AmazonEC2", ec2Filter("regionCode", req.Region), ec2Filter("instanceType", req.Plan), ec2Filter("operatingSystem", "Linux"), ec2Filter("tenancy", "Shared"), ec2Filter("preInstalledSw", "NA"), ec2Filter("capacitystatus", "Used"), ec2Filter("operation", "RunInstances"))
	if err != nil {
		return c, err
	}
	rate, err := ec2FixedRate(products, "Hrs")
	if err != nil {
		return c, fmt.Errorf("EC2 compute quote: %w", err)
	}
	c.Compute = rate * 730
	products, err = s.ec2Prices(ctx, req, "AmazonEC2", ec2Filter("regionCode", req.Region), ec2Filter("volumeApiName", "gp3"))
	if err != nil {
		return c, err
	}
	// gp3 throughput and IOPS products share volumeApiName. Only base Storage is required.
	var storage []map[string]any
	for _, p := range products {
		if str(obj(p["product"])["productFamily"]) == "Storage" {
			storage = append(storage, p)
		}
	}
	rate, err = ec2FixedRate(storage, "GB-Mo")
	if err != nil {
		return c, fmt.Errorf("EC2 gp3 quote: %w", err)
	}
	c.Disk = rate * float64(diskGB)
	products, err = s.ec2Prices(ctx, req, "AmazonVPC", ec2Filter("regionCode", req.Region), ec2Filter("group", "VPCPublicIPv4Address"))
	if err != nil {
		return c, err
	}
	var ipv4, idleIPv4 []map[string]any
	for _, p := range products {
		usage := str(obj(obj(p["product"])["attributes"])["usagetype"])
		if strings.HasSuffix(usage, "PublicIPv4:InUseAddress") {
			ipv4 = append(ipv4, p)
		}
		if strings.HasSuffix(usage, "PublicIPv4:IdleAddress") {
			idleIPv4 = append(idleIPv4, p)
		}
	}
	rate, err = ec2FixedRate(ipv4, "Hrs")
	if err != nil {
		return c, fmt.Errorf("EC2 public IPv4 quote: %w", err)
	}
	c.IPv4 = rate * 730
	rate, err = ec2FixedRate(idleIPv4, "Hrs")
	if err != nil {
		return c, fmt.Errorf("EC2 idle public IPv4 quote: %w", err)
	}
	c.IdleIPv4 = rate * 730
	products, err = s.ec2Prices(ctx, req, "AWSDataTransfer", ec2Filter("fromRegionCode", req.Region), ec2Filter("transferType", "AWS Outbound"), ec2Filter("toLocation", "External"))
	if err != nil {
		return c, err
	}
	if len(products) != 1 {
		return c, fmt.Errorf("EC2 internet transfer price is ambiguous or unavailable")
	}
	c.Transfer, err = ec2Dimensions(products)
	if err != nil {
		return c, err
	}
	sort.Slice(c.Transfer, func(i, j int) bool { return c.Transfer[i].Begin < c.Transfer[j].Begin })
	next := float64(0)
	for _, d := range c.Transfer {
		if d.Begin != next || d.Unit != "GB" || d.USD <= 0 {
			return c, fmt.Errorf("EC2 internet transfer ranges are incomplete or include shared allowances")
		}
		next = d.End
	}
	if !math.IsInf(next, 1) {
		return c, fmt.Errorf("EC2 internet transfer price lacks its final tier")
	}
	return c, nil
}
