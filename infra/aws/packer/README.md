# Build the Shirudo AWS AMI

Use the Packer wrapper in this directory to build an Ubuntu AMI with the
bpf-next kernel. Target images are the default; choose `image_role=dev` for a
development AMI without Shirudo provisioning.

## Requirements

- Packer
- AWS credentials with permission to create the temporary builder role and
  instance profile, launch and configure EC2 instances, and register and tag
  AMIs
- The AWS Session Manager plugin
- GitHub CLI (`gh`), authenticated to GitHub with Actions read access to
  `shirudo-dev/kernel` and `shirudo-dev/shirudo`

The wrapper and Packer use the AWS credentials in your environment. Set
`AWS_PROFILE` to choose a profile, and check the selected account with
`aws sts get-caller-identity` before building.

The wrapper uses the latest successful kernel package run from
`shirudo-dev/kernel:main`. Target builds also use the latest successful package
and image-assets runs from `shirudo-dev/shirudo:main`. Start those workflows
before building if you need them to publish new artifacts.

## Embed an additional config verification certificate

Target image builds can embed an additional config verification certificate.
This lets a downstream operator sign live config updates with a private key
that stays outside upstream CI and the AMI.

1. Generate a config signing key once on the downstream operator host and keep
   its private key secure:

   ```bash
   shirudo genkey --keys-dir /secure/path/config-signing
   ```

2. Base64-encode the public DER certificate:

   ```bash
   base64 -i /secure/path/config-signing/cert.der | tr -d '\n'
   ```

3. Dispatch the **Build packages** workflow on `main` with the
   `additional_config_cert` input set to that base64 value. The input is the
   public certificate; never submit `signing_key.pem`.

4. After the workflow succeeds, build the AMI using that workflow run's ID:

   ```bash
   ./scripts/build-with-temporary-instance-profile.sh \
     --shirudo-image-assets-run-id IMAGE_ASSETS_RUN_ID \
     .
   ```

The workflow signs the initial config with its temporary key and embeds the
downstream certificate in the runtime. Keep the matching downstream
`signing_key.pem` to sign future config images, then activate them with
`shirudo image update`.

## Build

From the Shirudo repository root:

```bash
cd infra/aws/packer
./scripts/build-with-temporary-instance-profile.sh .
```

Build a dev AMI by setting `image_role`:

```bash
./scripts/build-with-temporary-instance-profile.sh \
  -var 'image_role=dev' \
  .
```

The wrapper creates and removes a temporary IAM role and instance profile for
the builder. Optional environment variables:

- `SSM_AUDIT_BUCKET`: existing S3 bucket for Session Manager session logs; the
  wrapper grants the temporary builder role access to it.

Use `additional_build_tags` for tags on the temporary builder instance and its
root volume, including `owner` and `expiry` if needed:

```bash
SSM_AUDIT_BUCKET=bucket-name \
./scripts/build-with-temporary-instance-profile.sh \
  -var 'additional_build_tags={owner="your-user", expiry="YYYY-MM-DD", custom_tag="value"}' \
  .
```

`additional_build_tags` applies to the temporary builder instance and its root
volume. The output AMI, snapshot, and temporary IAM role and profile do not
receive these tags.

## Select artifacts

The wrapper selects the latest successful artifacts by default. Pin specific
workflow runs with these options:

```bash
./scripts/build-with-temporary-instance-profile.sh \
  -var 'kernel_github_run_id=KERNEL_RUN_ID' \
  -var 'shirudo_github_run_id=SHIRUDO_PACKAGES_RUN_ID' \
  --shirudo-image-assets-run-id IMAGE_ASSETS_RUN_ID \
  .
```

Other Packer options can be passed as `-var` arguments, including `region`,
`instance_type` and `root_volume_size`. The wrapper initializes Packer and
builds the AMI.
