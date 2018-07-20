package jwt

import (
	"fmt"
	"testing"

	r "github.com/hashicorp/terraform/helper/resource"
	"github.com/hashicorp/terraform/terraform"
)

func TestHashedJWT(t *testing.T) {
	r.Test(t, r.TestCase{
		Providers: testProviders,
		Steps: []r.TestStep{
			r.TestStep{
				Config: `
                    resource "jwt_hashed_token" "example" {
						algorithm = "HS512"
						secret    = "notthegreatestkey"

						claims = {
							a = "b"
						}
					}

					output "example_token" {
						value = "${jwt_hashed_token.example.token}"
					}
                `,
				Check: func(s *terraform.State) error {
					gotTokenUntyped := s.RootModule().Outputs["example_token"].Value
					gotToken, ok := gotTokenUntyped.(string)
					if !ok {
						return fmt.Errorf("output for \"example_token\" is not a string")
					}

					if gotToken != "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJhIjoiYiJ9.cl5DXDjjNUqWzYcsSOvljSs9skgxV7xrxXr6IFXdN_FEYe7qOw-IsWBQBAyB1Ra3kfngwT9h2VK1YuT00Qp-rg" {
						return fmt.Errorf("Token miscalculated")
					}

					return nil
				},
			},
		},
	})
}
