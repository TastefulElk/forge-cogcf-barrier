# CogCF Barrier

The _CogCF Barrier_ (or simply barrier) is an application based on AWS SAM to restrict access to a CloudFront
distribution. It requires a Cognito User Pool with a configured domain to handle the login process.

The article [Restricting access to CloudFront Distributions](https://codesmith/blog/2019-11-05-cogcf-barrier/) 
explains how the barrier works.

## Installation

To install the barrier, you need the following:

1. the [aws](https://aws.amazon.com/cli/) cli tool;
2. a configured AWS Profile to connect to your AWS account;
3. Python 3.7;
4. the [poetry](https://poetry.eustace.io) dependency manager for Python;
5. a Cognito User Pool with a configured domain;
6. an existing CloudFront distribution or a domain name that will be used for a future CloudFront distribution.
7. [set up CloudWatch logging for the AWS API Gateway](https://docs.aws.amazon.com/apigateway/latest/developerguide/set-up-logging.html)
in the region where the barrier will be installed.

Do the following steps:

<ol>
<li>copy the file <code>assembly.template.yaml</code> and fill in the configuration</li>
<li>run <code>poetry run deploy -f &lt;assembly file&gt;</code> and wait for the output; it will be similar to the next table.

<table class="sql-table">
<tbody>
<tr>
<td>Session Manager Origin Host</td>
<td><code>XXXXXXX.execute-api.XX-XXXX-X.amazonaws.com</code></td>
</tr>

<tr>
<td>Session Manager Origin Path</td>
<td><code>/prod</code></td>
</tr>

<tr>
<td>Session Checker Function Arn</td>
<td><code>arn:aws:lambda:us-east-1:999999999999:function:XXXXX:1</code></td>
</tr>
</tbody>
</table>

</li>
<li>Update or create a CloudFront distribution so that

1. There is an origin for the `Session Manager Origin Host` with the path `Session Manager Origin Path`;
2. There is a behavior for that origin with the path pattern `/_identity/*`;
3. All origins that needs to be restricted have the `Session Checker Function Arn` as viewer request lambda
association on their behaviors.

</li>

</ol>

You can use `poetry run info-json -f  <assembly file>` to print the values in the table above a json document.

## Custom Origins

If you use a custom origin, it will be a publically available server. If you want such origin to be protected, you will
need to verify the session a second time, on the origin, when the request is forwarded by CloudFront. The session checker
will forward the session cookie to the origin as well as a custom header `X-Barrier-Session-Id` containing the session id.

The CloudFormation template for the session manager creates a managed policy for read access to the session table. You
can use this policy to configure permissions of your custom origin.

## Running tests

To run the tests, you need the following:

1. a running Docker runtime: the tests uses the [dynamodb-local](https://hub.docker.com/r/amazon/dynamodb-local/) Docker image.
2. a configured AWS Profile named `forge-test`: the tests installs a CloudFormation template with a Cognito User Pool on
   the us-east-1 region for this profile; we recommand to use a developer account.
3. the [tox](https://tox.readthedocs.io/en/latest/) tool.

To run the tests, just invoke the tox tool on your terminal:

```
tox
```
