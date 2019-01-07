defmodule FireAuth.TokenValidation do
  @moduledoc """
  Validation of firebase id_tokens.
  """
  require FireAuth.Util
  alias FireAuth.Util

  @doc """
  Validates a give token_string.
  This checks if the string was signed properly and is still valid.

  If this is true
  {:ok, 
    %{name: name, id: id, email: email, email_verified: email_verified, provider_id: provider_id}}
  is returned.

  In case there are any problems a error in the form
  {:error, error_message}
  is returned.
  """
  def validate_token(token_string) do
    token = Joken.token(token_string)
    header = Joken.peek_header(token)

    with {:ok, claims} <- verify_token(token, header) do
      if check_token_claims(claims) do
        {:ok, claims}
      else
        {:error, "Token claims are invalid. (The token might be expired or the project_id might be wrong)"}
      end
    end
  end

  # checks that all requirements are met for the token claims
  defp check_token_claims(claims) do
    check_token_claims_exp(claims) &&
    check_token_claims_iat(claims) &&
    check_token_claims_aud(claims) &&
    check_token_claims_iss(claims)
  end

  defp check_token_claims_exp(claims), do: Util.current_time() <= claims["exp"]
  defp check_token_claims_iat(claims), do: Util.current_time() >= claims["iat"]
  defp check_token_claims_aud(claims), do: claims["aud"] in project_ids()
  defp check_token_claims_iss(claims) do
    claims["iss"] in Enum.map(project_ids(), & "https://securetoken.google.com/#{&1}")
  end

  # verifies a token using the keybase fetched from firebase.
  # returns
  #   {:ok, claims} when the token was verified successfully
  #   {:error, error_message} otherwise
  defp verify_token(token, %{"alg" => "RS256", "kid" => kid}) do
    cert = Map.get(FireAuth.KeyServer.get_keybase(), kid)

    case cert do
      nil ->
        {:error, "Could not find public certificate matching token kid."}
      cert ->
        jwk =
          cert
          |> decode_cert() # decode the cert read from googles json
          |> Util.otp_certificate(:tbsCertificate) # use records to get the part we need
          |> Util.otptbs_certificate(:subjectPublicKeyInfo)
          |> Util.otp_subject_public_key_info(:subjectPublicKey)
          |> JOSE.JWK.from_key() # create our JWK token form it

        # Validate the token
        # This returns the token with possible verify errors
        verified_token = token
                          |> Joken.with_signer(Joken.rs256(jwk))
                          |> Joken.verify

        case verified_token do
          %{error: nil, claims: claims} ->
            {:ok, claims}
          %{error: error} ->
            {:error, "Token verifikation failed. #{inspect(error)}"}
          _ ->
            {:error, "Token verifikation failed. Unkonwn result."}
        end
    end
  end

  defp verify_token(_, _) do
    {:error, "Wrong algorithm in token header."}
  end

  # decodes the certificate with the kid given in the token id
  defp decode_cert(cert) do
    [{:Certificate, cert_entry, :not_encrypted}] = :public_key.pem_decode(cert)
    :public_key.pkix_decode_cert(cert_entry, :otp)
  end

  defp project_ids() do
    case Application.get_env(:fire_auth, :project_id) do
      nil ->
        Application.get_env(:fire_auth, :project_ids) ||
          raise ":fire_auth, :project_id not set! Please add it to your config file."

      project_id -> [project_id]
    end
  end
end
