(ns kotoba.lang.crypto-test
  (:require [clojure.test :refer [deftest is testing]]
            [kotoba.lang.crypto :as crypto])
  (:import [java.security MessageDigest]))

(defn- expected-sha256 [data]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (.digest md (byte-array data))))

(defn- bytes->vec [b] (vec b))

(deftest sha256-hash
  (let [d [104 101 108 108 111]  ; "hello"
        h (crypto/hash d)]
    (is (= 32 (count (bytes->vec h))))
    (is (= (bytes->vec (expected-sha256 d)) (bytes->vec h)))))

(deftest sha512-hash
  (let [d [104 101 108 108 111]
        h (crypto/hash :sha512 d)]
    (is (= 64 (count (bytes->vec h))))))

(deftest hmac-sha256
  (let [key (vec (repeat 32 1))
        data [1 2 3 4 5]
        mac (crypto/hmac key data)]
    (is (= 32 (count (bytes->vec mac))))
    ;; deterministic
    (is (= (bytes->vec mac) (bytes->vec (crypto/hmac key data))))))

(deftest hkdf
  (let [ikm [1 2 3 4 5 6 7 8]
        info [255 254]
        out (crypto/hkdf ikm info 64)]
    (is (= 64 (count (bytes->vec out))))
    ;; different info -> different output
    (is (not= (bytes->vec out) (bytes->vec (crypto/hkdf ikm [1 2] 64))))))

(deftest aead-roundtrip
  (let [aead (crypto/mock-aead)
        key [1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16]
        nonce [255 254 253 252]
        pt [10 20 30 40 50]
        aad [99 98]
        {:keys [ciphertext tag]} (crypto/encrypt aead key nonce pt aad)]
    (is (= (count pt) (count (bytes->vec ciphertext))))
    (let [dec (crypto/decrypt aead key nonce ciphertext tag aad)]
      (is (= pt (bytes->vec dec))))))

(deftest aead-tamper-fails
  (let [aead (crypto/mock-aead)
        key [1 2 3 4]
        nonce [9 9]
        pt [1 2 3]
        {:keys [ciphertext tag]} (crypto/encrypt aead key nonce pt [])]
    (is (thrown? clojure.lang.ExceptionInfo
                (crypto/decrypt aead key nonce ciphertext (byte-array [0 0 0]) [])))))
