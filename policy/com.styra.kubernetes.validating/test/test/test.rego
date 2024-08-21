package policy["com.styra.kubernetes.validating"].test.test

test_allow_get {
    result := data.example.policy.allow with input as {"method": "GET"}
    result == true
}

test_deny_post {
    result := data.example.policy.allow with input as {"method": "POST"}
    result == false
}