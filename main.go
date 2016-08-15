package main

//go:generate ./version.sh

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/aws/aws-sdk-go/service/elb"
	"github.com/aws/aws-sdk-go/service/rds"

	yaml "gopkg.in/yaml.v2"
)

type Configuration struct {
	Components []Component `json:"components" yaml:"components"`
	Rules      []Rule      `json:"rules" yaml:"rules"`
	AWS        AWS         `json:"aws" yaml:"aws"`
}
type Component struct {
	Name string `json:"name" yaml:"name"`
	Type string `json:"type" yaml:"type"`
	Tag  Tag    `json:"tag" yaml:"tag"`
}
type Tag struct {
	Key   string `json:"key" yaml:"key"`
	Value string `json:"value" yaml:"value"`
}
type Rule struct {
	Src   string `json:"src" yaml:"src"`
	Sport int    `json:"sport" yaml:"sport"`
	Dst   string `json:"dst" yaml:"dst"`
	Dport int    `json:"dport" yaml:"dport"`
}
type AWS struct {
	AccessKey     string `json:"accesskey" yaml:"accesskey"`
	SecretKey     string `json:"secretkey" yaml:"secretkey"`
	Region        string `json:"region" yaml:"region"`
	AccountNumber int    `json:"accountnumber" yaml:"accountnumber"`
}

var config = flag.String("c", "", "Load configuration from file. Use stdin if omitted.")
var showVersion = flag.Bool("V", false, "Show version and exit")

func main() {
	var (
		err  error
		conf Configuration
	)

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s - Network Access Control Policy Inspector\n"+
			"Usage: %s [-c config.yaml]\n",
			os.Args[0], os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		os.Exit(0)
	}

	// load the local configuration file
	var data []byte
	if *config == "" {
		data, err = ioutil.ReadAll(os.Stdin)
		// or read conf from stdin
	} else {
		data, err = ioutil.ReadFile(*config)
	}
	if err != nil {
		log.Fatal(err)
	}
	err = yaml.Unmarshal(data, &conf)
	if err != nil {
		log.Fatalf("error: %v", err)
	}

	// the security groups of each component are stored in
	// a global map used to check access controls later
	sgmap := make(map[string][]*ec2.SecurityGroup)
	log.Println("building map of security groups for all", len(conf.Components), "components")
	for _, comp := range conf.Components {
		if comp.Type == "" || comp.Name == "" || comp.Tag.Key == "" || comp.Tag.Value == "" {
			log.Fatalf("invalid configuration for %q component %q. Make sure every component has a type, name tag key and value",
				comp.Type, comp.Name)
		}
		switch comp.Type {
		case "rds":
			sgmap[comp.Name], err = getRDSSecurityGroups(conf, comp.Tag)
		case "elb":
			sgmap[comp.Name], err = getELBSecurityGroups(conf, comp.Tag)
		case "ec2":
			sgmap[comp.Name], err = getEC2SecurityGroups(conf, comp.Tag)
		default:
			log.Fatalf("component type %q is not supported", comp.Type)
		}
		if err != nil {
			log.Fatalf("failed to get security groups for %q component %q: %v",
				comp.Type, comp.Name, err)
		}
	}

	// evaluate rules
	for i, rule := range conf.Rules {
		verifyRule(rule, i, sgmap)
	}
}

// returns the security groups of an RDS instance identified by a tag
func getRDSSecurityGroups(conf Configuration, tag Tag) ([]*ec2.SecurityGroup, error) {
	awsconf := aws.Config{
		Region: aws.String(conf.AWS.Region),
	}
	if conf.AWS.AccessKey != "" && conf.AWS.SecretKey != "" {
		awscreds := credentials.NewStaticCredentials(conf.AWS.AccessKey, conf.AWS.SecretKey, "")
		awsconf.Credentials = awscreds
	}
	svc := rds.New(session.New(), &awsconf)
	svcec2 := ec2.New(session.New(), &awsconf)

	dbis, err := svc.DescribeDBInstances(nil)
	if err != nil {
		log.Println("failed to obtain list of RDS instances:", err.Error())
		return nil, err
	}
	for _, dbi := range dbis.DBInstances {
		ismatch := false
		rid := fmt.Sprintf("arn:aws:rds:%s:%d:db:%s",
			conf.AWS.Region, conf.AWS.AccountNumber, *dbi.DBInstanceIdentifier)
		var dbtags *rds.ListTagsForResourceOutput
		dbtags, err = svc.ListTagsForResource(&rds.ListTagsForResourceInput{
			ResourceName: aws.String(rid),
		})
		if err != nil {
			log.Printf("failed to obtain tags of RDS instances %q: %v",
				rid, err.Error())
			return nil, err
		}
		for _, dbtag := range dbtags.TagList {
			if *dbtag.Key == tag.Key && *dbtag.Value == tag.Value {
				log.Printf("%q matches tags %s:%s", rid, tag.Key, tag.Value)
				ismatch = true
			}
		}
		if ismatch {
			// get the security groups and exit
			var sgids []*string
			for _, vpcsgid := range dbi.VpcSecurityGroups {
				sgids = append(sgids, vpcsgid.VpcSecurityGroupId)
			}
			dsgo, err := svcec2.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
				GroupIds: sgids,
			})
			return dsgo.SecurityGroups, err
		}
	}
	return nil, fmt.Errorf("no instance found matching tags %+v", tag)
}

func getELBSecurityGroups(conf Configuration, tag Tag) ([]*ec2.SecurityGroup, error) {
	awsconf := aws.Config{
		Region: aws.String(conf.AWS.Region),
	}
	if conf.AWS.AccessKey != "" && conf.AWS.SecretKey != "" {
		awscreds := credentials.NewStaticCredentials(conf.AWS.AccessKey, conf.AWS.SecretKey, "")
		awsconf.Credentials = awscreds
	}
	svc := elb.New(session.New(), &awsconf)
	svcec2 := ec2.New(session.New(), &awsconf)
	elbinstances, err := svc.DescribeLoadBalancers(nil)
	if err != nil {
		log.Printf("failed to obtain ELB descriptions: %v", err)
		return nil, err
	}
	for _, elbis := range elbinstances.LoadBalancerDescriptions {
		ismatch := false
		elbtags, err := svc.DescribeTags(&elb.DescribeTagsInput{
			LoadBalancerNames: []*string{elbis.LoadBalancerName},
		})
		if err != nil {
			log.Printf("failed to obtain tags of ELB instance %q: %v",
				*elbis.LoadBalancerName, err.Error())
			return nil, err
		}
		for _, td := range elbtags.TagDescriptions {
			for _, elbtag := range td.Tags {
				if *elbtag.Key == tag.Key && *elbtag.Value == tag.Value {
					log.Printf("%q matches tags %s:%s",
						*elbis.LoadBalancerName, tag.Key, tag.Value)
					ismatch = true
				}
			}
		}
		if ismatch {
			elbsgo, err := svcec2.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
				GroupIds: elbis.SecurityGroups,
			})
			return elbsgo.SecurityGroups, err
		}
	}
	return nil, fmt.Errorf("no instance found matching tags %+v", tag)
}

func getEC2SecurityGroups(conf Configuration, tag Tag) ([]*ec2.SecurityGroup, error) {
	awsconf := aws.Config{
		Region: aws.String(conf.AWS.Region),
	}
	if conf.AWS.AccessKey != "" && conf.AWS.SecretKey != "" {
		awscreds := credentials.NewStaticCredentials(conf.AWS.AccessKey, conf.AWS.SecretKey, "")
		awsconf.Credentials = awscreds
	}
	svc := ec2.New(session.New(), &awsconf)
	ec2instances, err := svc.DescribeInstances(&ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			{
				Name: aws.String("tag:" + tag.Key),
				Values: []*string{
					aws.String(tag.Value),
				},
			},
		},
	})
	if err != nil {
		log.Printf("failed to obtain EC2 descriptions: %v", err)
		return nil, err
	}
	for _, reservation := range ec2instances.Reservations {
		for _, instance := range reservation.Instances {
			log.Printf("%q matches tags %s:%s",
				*instance.InstanceId, tag.Key, tag.Value)
			var sgids []*string
			for _, gid := range instance.SecurityGroups {
				sgids = append(sgids, gid.GroupId)
			}
			ec2sgo, err := svc.DescribeSecurityGroups(&ec2.DescribeSecurityGroupsInput{
				GroupIds: sgids,
			})
			return ec2sgo.SecurityGroups, err
		}
	}
	return nil, fmt.Errorf("no instance found matching tags %+v", tag)
}

func verifyRule(rule Rule, rulenum int, sgmap map[string][]*ec2.SecurityGroup) {
	var (
		permitted    bool = false
		sport, dport bool = true, true
		src          bool = false
	)
	if _, ok := sgmap[rule.Dst]; !ok {
		return
	}
	// verify the destination authorize the origin sg and port
	for _, sg := range sgmap[rule.Dst] {
		for _, ipperm := range sg.IpPermissions {
			if rule.Sport > 0 {
				sport = false
			}
			if rule.Dport > 0 {
				dport = false
			}
			if *ipperm.FromPort == int64(rule.Sport) {
				sport = true
			}
			if *ipperm.ToPort == int64(rule.Dport) {
				dport = true
			}
			// at least one of the src security groups must be authorized
			// to connect to the destination security group
			for _, uidgroup := range ipperm.UserIdGroupPairs {
				for _, sg := range sgmap[rule.Src] {
					if *uidgroup.GroupId == *sg.GroupId {
						src = true
					}
				}
			}
			// if src is an ip, check presence in ipranges
			for _, iprange := range ipperm.IpRanges {
				if *iprange.CidrIp == rule.Src {
					src = true
				}
			}
			if src && sport && dport {
				permitted = true
				break
			}
		}
	}
	if permitted {
		log.Printf("rule %d between %q and %q was found",
			rulenum, rule.Src, rule.Dst)
	} else {
		log.Fatalf("FAILURE: rule %d between %q and %q was NOT found",
			rulenum, rule.Src, rule.Dst)
	}
}
