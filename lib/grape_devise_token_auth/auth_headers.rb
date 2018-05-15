module GrapeDeviseTokenAuth
  class AuthHeaders
    extend Forwardable

    def initialize(warden, mapping, request_start, data)
      @resource = warden.user(:user)
      @request_start = request_start
      @data = data
    end

    def headers
      return {} unless resource && resource.valid? && client_id
      auth_headers_from_resource
    end

    private

    def_delegators :@data, :token, :client_id
    attr_reader :request_start, :resource

    def batch_request?
      @batch_request ||= resource.tokens[client_id] &&
                         resource.tokens[client_id]['updated_at'] &&
                         within_batch_request_window?
    end

    def within_batch_request_window?
      end_of_window = Time.parse(resource.tokens[client_id]['updated_at']) +
                      GrapeDeviseTokenAuth.batch_request_buffer_throttle

      request_start < end_of_window
    end

    def auth_headers_from_resource
      auth_headers = {}
      resource.with_lock do
        if batch_request?
          # extend expiration of batch buffer to account for the duration of
          # this request
          auth_headers = resource.extend_batch_buffer(token, client_id)

          # Do not return token for batch requests to avoid invalidated
          # tokens returned to the client in case of race conditions.
          # Use a blank string for the header to still be present and
          # being passed in a XHR response in case of
          # 304 Not Modified responses.
          auth_headers[DeviseTokenAuth.headers_names[:"access-token"]] = ' '
          auth_headers[DeviseTokenAuth.headers_names[:"expiry"]] = ' '
        else
          # update Authorization response header with new token
          auth_headers = resource.create_new_auth_token(client_id)
        end
      end
      auth_headers
    end
  end
end
