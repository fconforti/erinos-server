FROM ruby:3.4-alpine

RUN apk add --no-cache build-base

WORKDIR /app

COPY Gemfile Gemfile.lock ./
RUN bundle config set without 'development test' && bundle install

COPY . .

EXPOSE 4568

CMD ["bundle", "exec", "rackup", "--host", "0.0.0.0", "--port", "4568"]
