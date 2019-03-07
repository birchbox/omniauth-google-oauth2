require 'omniauth/strategies/oauth2'
require 'uri'

module OmniAuth
  module Strategies
    class GoogleOauth2 < OmniAuth::Strategies::OAuth2
      BASE_SCOPE_URL = "https://www.googleapis.com/auth/"
      BASE_SCOPES = %w[profile email openid]
      DEFAULT_SCOPE = "email,profile"
      USER_INFO_URL = 'https://www.googleapis.com/oauth2/v3/userinfo'
      TOKEN_INFO_URL = 'https://www.googleapis.com/oauth2/v3/tokeninfo'


      option :name, 'google_oauth2'

      option :skip_friends, true

      option :authorize_options, [:access_type, :hd, :login_hint, :prompt, :request_visible_actions, :scope, :state, :redirect_uri, :include_granted_scopes]

      option :client_options, {
        :site          => 'https://oauth2.googleapis.com',
        :authorize_url => 'https://accounts.google.com/o/oauth2/auth',
        :token_url     => '/token'
      }

      def authorize_params
        super.tap do |params|
          options[:authorize_options].each do |k|
            params[k] = request.params[k.to_s] unless [nil, ''].include?(request.params[k.to_s])
          end

          raw_scope = params[:scope] || DEFAULT_SCOPE
          scope_list = raw_scope.split(" ").map {|item| item.split(",")}.flatten
          scope_list.map! { |s| s =~ /^https?:\/\// || BASE_SCOPES.include?(s) ? s : "#{BASE_SCOPE_URL}#{s}" }
          params[:scope] = scope_list.join(" ")
          params[:access_type] = 'offline' if params[:access_type].nil?

          session['omniauth.state'] = params[:state] if params['state']
        end
      end

      uid { raw_info['sub'] || verified_email }

      info do
        prune!({
          :name       => raw_info['name'],
          :email      => verified_email,
          :first_name => raw_info['given_name'],
          :last_name  => raw_info['family_name'],
          :image      => image_url,
          :urls => {
            'Google' => raw_info['profile']
          }
        })
      end

      extra do
        hash = {}
        hash[:id_token] = access_token['id_token']
        hash[:raw_info] = raw_info unless skip_info?
        prune! hash
      end

      def raw_info
        @raw_info ||= access_token.get(USER_INFO_URL).parsed
      end

      def custom_build_access_token
        if request.xhr? && request.params['code']
          verifier = request.params['code']
          redirect_uri = request.params['redirect_uri'] || 'postmessage'
          client.auth_code.get_token(verifier, get_token_options(redirect_uri), deep_symbolize(options.auth_token_params || {}))
        elsif request.params['code'] && request.params['redirect_uri']
          verifier = request.params['code']
          redirect_uri = request.params['redirect_uri']
          client.auth_code.get_token(verifier, get_token_options(redirect_uri), deep_symbolize(options.auth_token_params || {}))
        elsif verify_token(request.params['access_token'])
          ::OAuth2::AccessToken.from_hash(client, request.params.dup)
        else
          verifier = request.params['code']
          client.auth_code.get_token(verifier, get_token_options(callback_url), deep_symbolize(options.auth_token_params))
        end
      end
      alias build_access_token custom_build_access_token

      private

      def callback_url
        options[:redirect_uri] || (full_host + script_name + callback_path)
      end

      def get_token_options(redirect_uri)
        { redirect_uri: redirect_uri }.merge(token_params.to_hash(symbolize_keys: true))
      end

      def verify_token(access_token)
        return false unless access_token

        raw_response = client.request(:get, TOKEN_INFO_URL,
                                      params: { access_token: access_token }).parsed
        raw_response['aud'] == options.client_id || options.authorized_client_ids.include?(raw_response['aud'])
      end

      def prune!(hash)
        hash.delete_if do |_, v|
          prune!(v) if v.is_a?(Hash)
          v.nil? || (v.respond_to?(:empty?) && v.empty?)
        end
      end

      def verified_email
        raw_info['email_verified'] ? raw_info['email'] : nil
      end

      def image_url
        return nil unless raw_info['picture']

        u = URI.parse(raw_info['picture'].gsub('https:https', 'https'))

        path_index = u.path.to_s.index('/photo.jpg')

        if path_index && image_size_opts_passed?
          u.path.insert(path_index, image_params)
          u.path = u.path.gsub('//', '/')
        end

        u.query = strip_unnecessary_query_parameters(u.query)

        u.to_s
      end

      def image_size_opts_passed?
        options[:image_size] || options[:image_aspect_ratio]
      end

      def image_params
        image_params = []
        if options[:image_size].is_a?(Integer)
          image_params << "s#{options[:image_size]}"
        elsif options[:image_size].is_a?(Hash)
          image_params << "w#{options[:image_size][:width]}" if options[:image_size][:width]
          image_params << "h#{options[:image_size][:height]}" if options[:image_size][:height]
        end
        image_params << 'c' if options[:image_aspect_ratio] == 'square'

        '/' + image_params.join('-')
      end

      def strip_unnecessary_query_parameters(query_parameters)
        # strip `sz` parameter (defaults to sz=50) which overrides `image_size` options
        return nil if query_parameters.nil?

        params = CGI.parse(query_parameters)
        stripped_params = params.delete_if { |key| key == 'sz' }

        # don't return an empty Hash since that would result
        # in URLs with a trailing ? character: http://image.url?
        return nil if stripped_params.empty?

        URI.encode_www_form(stripped_params)
      end
    end
  end
end
