package main

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_user"
  not resource.change.after.tags.env
  msg = sprintf("Missing required tag 'env' for IAM User named '%s'.", [resource.change.after.name])
}

deny[msg] {
  resource := input.resource_changes[_]
  resource.type == "aws_iam_user"
  not resource.change.after.tags.owner
  msg = sprintf("Missing required tag 'owner' for IAM User named '%s'.", [resource.change.after.name])
}
