require 'net/http'
require 'uri'

class JsonWebToken
  #https://auth0.com/docs/api-auth/tutorials/verify-access-token
  #https://auth0.com/docs/quickstart/backend/rails/01-authorization
  #https://manage.auth0.com/#/clients
  def self.verify(token, aud)
    JWT.decode(token, nil,
               true, # Verify the signature of this token
               algorithm: 'RS256',
               iss: 'https://finan.auth0.com/',
               verify_iss: true,
               # auth0_api_audience is the identifier for the API set up in the Auth0 dashboard
               #aud: 'http://localhost:3002/indexes/endpoint.json',
               aud: aud,
               verify_aud: true) do |header|
      jwks_hash[header['kid']]
    end
  end

  def self.jwks_hash
    jwks_raw = Net::HTTP.get URI("https://finan.auth0.com/.well-known/jwks.json")
    jwks_keys = Array(JSON.parse(jwks_raw)['keys'])
    Hash[
        jwks_keys
            .map do |k|
          [
              k['kid'],
              OpenSSL::X509::Certificate.new(
                  Base64.decode64(k['x5c'].first)
              ).public_key
          ]
        end
    ]
  end
end

class UsersController < ApplicationController
  before_action :set_user, only: [:show, :edit, :update, :destroy]

  def endpoint
    tier = 'free'
    if !params[:idToken].blank? && !params[:aud].blank?
      @auth_payload, @auth_header = JsonWebToken.verify(params[:idToken], params[:aud])
      user = User.where("email = ?", @auth_payload['email']).first
      if user.blank? && !@auth_payload['email'].blank? && !@auth_payload['sub'].blank?
        user = User.new({'email' => @auth_payload['email'], 'sub' => @auth_payload['sub'], 'tier' => 'free' })
        user.save
      end
      tier = user.tier
    end

    predictions_raw = Net::HTTP.get URI("http://localhost:3002/indexes/get_predictions.json")
    predictions = JSON.parse(JSON.parse(predictions_raw)['predictions'])

    render :json => {:success => true, :tier => tier, :predictions =>predictions}
  end

  # GET /users
  # GET /users.json
  def index
    @users = User.all
  end

  # GET /users/1
  # GET /users/1.json
  def show
  end

  # GET /users/new
  def new
    @user = User.new
  end

  # GET /users/1/edit
  def edit
  end

  # POST /users
  # POST /users.json
  def create
    @user = User.new(user_params)

    respond_to do |format|
      if @user.save
        format.html { redirect_to @user, notice: 'User was successfully created.' }
        format.json { render :show, status: :created, location: @user }
      else
        format.html { render :new }
        format.json { render json: @user.errors, status: :unprocessable_entity }
      end
    end
  end

  # PATCH/PUT /users/1
  # PATCH/PUT /users/1.json
  def update
    respond_to do |format|
      if @user.update(user_params)
        format.html { redirect_to @user, notice: 'User was successfully updated.' }
        format.json { render :show, status: :ok, location: @user }
      else
        format.html { render :edit }
        format.json { render json: @user.errors, status: :unprocessable_entity }
      end
    end
  end

  # DELETE /users/1
  # DELETE /users/1.json
  def destroy
    @user.destroy
    respond_to do |format|
      format.html { redirect_to users_url, notice: 'User was successfully destroyed.' }
      format.json { head :no_content }
    end
  end

  private
    # Use callbacks to share common setup or constraints between actions.
    def set_user
      @user = User.find(params[:id])
    end

    # Never trust parameters from the scary internet, only allow the white list through.
    def user_params
      params.require(:user).permit(:email, :sub, :tier)
    end
end
