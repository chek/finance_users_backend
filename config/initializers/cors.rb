#https://til.hashrocket.com/posts/4d7f12b213-rails-5-api-and-cors
Rails.application.config.middleware.insert_before 0, Rack::Cors do
  allow do
    origins 'localhost:3001'
    resource '*',
             headers: :any,
             methods: %i(get post put patch delete options head)
  end
end