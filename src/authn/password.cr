require "bcrypt"
require "password-policy"

module Authn
  # BCrypt password hashing.
  #
  # Hashing only. The rules a password must satisfy moved to
  # `aloli-crystal/password-policy`, where they belong: they are a policy
  # question, they change with the regulator — the CNIL replaced its 2017
  # composition rules with entropy tiers in 2022 — and keeping them here meant
  # every consumer inherited one hardcoded French wording.
  module Password
    # 12 is a defensible compromise between cost to an attacker and latency for
    # a user. Raise it as hardware improves; existing hashes carry their own
    # cost and keep verifying.
    DEFAULT_COST = 12

    # Longest password BCrypt accepts here, in **bytes** — not characters.
    # "Éducation" is nine characters and ten bytes, so an accented passphrase
    # reaches the ceiling sooner than its length suggests.
    #
    # 71, not the 72 usually quoted: Crystal's `Crypto::Bcrypt` appends a NUL
    # terminator (`password.bytesize + 1`) and rejects anything past 72, so 72
    # bytes of password become 73 and fail. Verified empirically — 71 hashes,
    # 72 raises.
    #
    # Worth noting for anyone porting from another language: Crystal *raises*
    # here, where the classic C implementations silently truncate. Raising is
    # the better failure, and it means this check duplicates a guarantee rather
    # than providing it — but the message it gives says which limit was hit.
    MAX_BYTESIZE = 71

    # Raised when a password fails the policy it was checked against.
    class PolicyError < Exception
      getter violations : Array(PasswordPolicy::Violation)

      def initialize(@violations : Array(PasswordPolicy::Violation))
        super("password rejected: #{@violations.join(", ")}")
      end
    end

    # Hash a plaintext password.
    #
    # Pass `policy` to enforce one; without it no policy is applied, and
    # checking the password is the caller's business.
    #
    # ```
    # Authn::Password.hash(submitted, policy: PasswordPolicy::Policy.long)
    # ```
    def self.hash(plain_password : String, cost : Int32 = DEFAULT_COST,
                  policy : PasswordPolicy::Policy? = nil) : String
      raise ArgumentError.new("the password must not be empty") if plain_password.empty?

      if plain_password.bytesize > MAX_BYTESIZE
        raise ArgumentError.new(
          "the password is #{plain_password.bytesize} bytes; BCrypt accepts at most #{MAX_BYTESIZE}"
        )
      end

      if policy
        violations = policy.validate(plain_password)
        raise PolicyError.new(violations) unless violations.empty?
      end

      BCrypt::Password.create(plain_password, cost: cost).to_s
    end

    # Whether a plaintext password matches a stored hash.
    #
    # Returns false rather than raising on a malformed hash: a caller checking
    # a password wants an answer, and a corrupt stored value is a failed
    # authentication, not an exceptional condition.
    def self.verify(plain_password : String, hashed_password : String) : Bool
      return false if plain_password.empty? || hashed_password.empty?
      BCrypt::Password.new(hashed_password).verify(plain_password)
    rescue
      false
    end
  end
end
