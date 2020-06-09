package vault_iam_auth

import (
	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/builtin/credential/aws"
)

func GetVaultTokenForEC2(vaultAddr string, vaultRole string) (auth *api.SecretAuth, err error) {
	loginData := make(map[string]interface{})
	loginData, err = awsauth.GenerateLoginData(nil, "", "us-east-1")
	if err != nil {
		return
	}
	loginData["role"] = vaultRole

	client, err := api.NewClient(&api.Config{Address: vaultAddr})
	if err != nil {
		return
	}
	secret, err := client.Logical().Write("auth/aws/login", loginData)
	if err != nil {
		return
	}

	auth = secret.Auth
	return
}