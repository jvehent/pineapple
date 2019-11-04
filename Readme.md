PineApple
=========

**P**olicy **I**nspector for **NE**twork **A**ccesses, **P**eo**PLE**!

<img src="https://raw.githubusercontent.com/jvehent/pineapple/master/statics/pineapple.png" width=200 >

This is a prototype to assert the content of security groups between AWS
components. It only supports ELB, EC2 and RDS at the moment. Doesn't do any
egress inspection and doesn't flag overly open groups. Basically, it's not ready
for production, but can be used to prototype infrastructure testing in CI.

If you're looking for a more mature alternative, consider [Mozilla's pytest-services](https://github.com/mozilla-services/pytest-services).

Pineapple uses tags to locate components in a given region, then pulls the security
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

Example run:
```bash
$ go get github.com/jvehent/pineapple

$ pineapple -c examples/invoicer.yaml

2016/08/14 23:37:55 building map of security groups for all 3 components
2016/08/14 23:37:58 "awseb-e-c-AWSEBLoa-1VXVTQLSGGMG5" matches tags elasticbeanstalk:environment-name:invoicer-api
2016/08/14 23:37:59 "i-7bdad5fc" matches tags elasticbeanstalk:environment-name:invoicer-api
2016/08/14 23:38:01 "arn:aws:rds:us-east-1:927034868273:db:invoicer201605211320" matches tags environment-name:invoicer-api
2016/08/14 23:38:01 rule 0 between "0.0.0.0/0" and "load-balancer" is permitted
2016/08/14 23:38:01 rule 1 between "load-balancer" and "application" is permitted
2016/08/14 23:38:01 rule 2 between "application" and "database" is permitted
```

Author
------
Julien Vehent - 2016

Credits
-------
PineApple is based on prior work from:

* [Dustin Mitchell](https://github.com/djmitche) who wrote
  [fwunit](https://github.com/mozilla/build-fwunit) years before I wrote PineApple
  and is definitely its strongest inspiration

* [Netflix's Security
  Monkey](https://github.com/Netflix/security_monkey) was a precursor in this
  field, but is a heavier solution that requires running a server.
