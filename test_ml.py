from detector.ml_classifier import predict_threat


test_cases = [
    "normal application activity",
    "application accessed microphone",
    "keylogging with network activity",
    "keylogging camera microphone network activity"
]


for behavior in test_cases:

    result = predict_threat(behavior)

    print("--------------------------------")

    print("Behavior:")
    print(behavior)

    print()

    print("Predicted Threat:")
    print(result["threat_level"])

    print(
        "Confidence:",
        result["confidence"],
        "%"
    )