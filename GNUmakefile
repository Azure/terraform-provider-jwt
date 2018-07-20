all: terraform-provider-jwt

terraform-provider-jwt:
	go build

install: terraform-provider-jwt
	cp terraform-provider-jwt ~/.terraform.d/plugins

test:
	cd jwt && TF_ACC=1 go test -test.v 

.PHONY: all install test
