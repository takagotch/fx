# sinatra 
# end user phone number convert to jwt

require 'jwt'

post "/verify/token" do
  param :phone_number, String, required: true

  payload = {
    app_id: ENV["APP_ID"],
    phone_number: params[:phone_number],
    iat: Time.now.to_i
  }

  jwt_token = JWT.encode(payload, ENV["AUTHY_API_KEY"], "HS256")

  response_with status: 200, body: {jwt_token: jwt_token}
end



