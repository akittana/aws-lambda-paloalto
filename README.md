# aws-lambda-paloalto

Python code for AWS Lambda that monitors changes in AWS and adds/removes rules automatically from a Palo Alto gateway instance running in AWS.
Current events monitored:
  * StartInstances: Event indicating that a new instance was started
  * AuthorizeSecurityGroupIngress: Event indicating that a new rule was adding to an existing security group
  * StopInstances: An instance was stopped.
  * RevokeSecurityGroupIngress: A rule was removed from a security group.

Before running, the following variables have to be set in the lambda.lambda_handler function:
  * pa_ip: IP address of your Palo Alto gateway.
  * pa_key: Access key for the Palo Alto gateway (Refer to the Pan-OS XML API User guide for more details on this, and specifically this page).
  * pa_bottom_rule: Name of the rule which the lambda function would be adding on top of. This would usually be the clean up rule in your security policy.
  * pa_zone_untrust: Name of the outside zone configured on the Palo Alto gateway.
  * pa_zone_trust: Name of the inside zone configured on the Palo Alto gateway.
  * pa_sgp: name of security profile group in Palo Alto to be set on rules added.
  * igwId: Instance id of the Palo Alto gateway.
  


