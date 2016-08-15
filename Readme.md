PineApple
=========

**P**olicy **I**nspector for **NE**twork **A**ccesses, **P**eo**PLE**!

![pineapple](statics/Bromeliaceae_1.png)

This is a prototype to assert the content of security groups between AWS
components. It only supports ELB, EC2 and RDS at the moment. Doesn't do any
egress inspection and doesn't flag overly open groups. Basically, it's not ready
for production, I'm just toying with the concept.

It uses tags to locate components in a given region, then pulls the security
groups of these components and compares their content against rules.

To run it, create a YAML configuration like the one below, and execute the
command `pineapple -c myconfig.yaml`. Make sure your `AWS_PROFILE` is set
correctly, and magic will happen!

```yaml
aws:
    region: us-east-1
    accountnumber: 927034868273

components:
    - name: load-balancer
      type: elb
      tag:
          key: elasticbeanstalk:environment-name
          value: invoicer-api

    - name: application
      type: ec2
      tag: 
          key: elasticbeanstalk:environment-name
          value: invoicer-api

    - name: database
      type: rds
      tag:
          key: environment-name
          value: invoicer-api

rules:
    - src: 0.0.0.0/0
      dst: load-balancer
      dport: 443

    - src: load-balancer
      dst: application
      dport: 80

    - src: application
      dst: database
      dport: 5432
```

Julien Vehent - Mozilla - 2016
