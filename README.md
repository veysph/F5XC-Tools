# F5 Distributed Cloud SMSv2 CEs deployment

This is a small collection of Terraform scripts to deploy F5XC SMSv2 CEs in various environments.

## Cloud topologies

For more information regarding use cases and SMSv2 CE implementation, please refer to this page on [F5 Devcentral](https://community.f5.com/kb/technicalarticles/how-to-deploy-an-f5xc-smsv2-site-with-the-help-of-automation/342198) and this page on [F5 XC Documentation](https://docs.cloud.f5.com/docs-v2/multi-cloud-network-connect/how-to/site-management/create-secure-mesh-site-v2).

In short the main topologies for single F5XC deployment in a cloud environment are the following.

**Internet Gateway or NAT Gateway topology**

![Cloud_IGW_NATGW](https://github.com/user-attachments/assets/52a7231f-bcda-43f2-a00f-fedb34dd6b4d)

**Proxy topology**

![MCN Use cases - CE - General Cloud IGW_NAT GW_Proxy](https://github.com/user-attachments/assets/3121a6a8-8378-4bc0-a1a5-f4a22e500f85)

## Cloud / F5XC subscription validation

**Azure**

```sh
az vm image terms accept --publisher f5-networks --offer f5xc_customer_edge --plan f5xccebyol
```

**AWS**

Go to this page in [AWS Console](https://aws.amazon.com/marketplace/search/results?searchTerms=F5+Distributed+Cloud+BYOL)

Then select "View purchase options" and then select "Subscribe".

# Support and license

This repository contains community code which is not covered by F5 Technical Support nor any SLA.

Please read and understand the [LICENSE](COPYING.txt) before use. 

The solutions in this repository are not guaranteed to work, keep working or being updated with required changes at any time.

You, as the implementor, are solely responsible.


## Last updated
July 11th 2025