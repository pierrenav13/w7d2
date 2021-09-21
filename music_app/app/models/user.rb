class User < ApplicationRecord
    after_initialize :generate_session_token

    validates :password_digest, presence: true
    validates :session_token, :email, presence: true, uniqueness: true

    def self.generate_session_token
        session[:session_token] = SecureRandom::urlsafe_base64
    end

    def self.find_by_credentials(email, password)
        user = User.find_by(params[:user][:email])

        if user && is_password?(password)
            user
        else
            nil
        end
    end

    def reset_session_token!
        self.session_token = SecureRandom::urlsafe_base64
    end

    def ensure_session_token
        self.session_token ||= SecureRandom::urlsafe_base64
    end

    def password=(password)
        self.password_digest = BCrypt::Password.create(password)
        @password = password
    end

    def is_password?(password)
        password_object = BCrypt::Password.new(self.password_digest)
        password_object.is_password?(password)
    end
end