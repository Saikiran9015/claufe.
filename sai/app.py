from flask import Flask, request, jsonify
import razorpay
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Use your Razorpay Keys
RAZOPAY_SECRET="OPWJbRo0DbtESPfSbokhbHz4"
RAZOPAY_KEY="rzp_test_23ine36FeN7gzT"

client = razorpay.Client(auth=(RAZOPAY_SECRET, RAZOPAY_KEY))


@app.post("/create-order")
def create_order():
    data = request.get_json()
    amount = data["amount"]

    # Creating Razorpay Order
    order = client.order.create({
        "amount": amount * 100,
        "currency": "INR",
        "payment_capture": 1
    })

    return jsonify({
        "order_id": order["id"],
        "amount": order["amount"],
        "currency": "INR",
        "key": RAZORPAY_KEY_ID
    })


@app.post("/verify-payment")
def verify_payment():
    data = request.get_json()

    try:
        client.utility.verify_payment_signature({
            "razorpay_order_id": data["razorpay_order_id"],
            "razorpay_payment_id": data["razorpay_payment_id"],
            "razorpay_signature": data["razorpay_signature"],
        })
        return jsonify({"success": True})
    except:
        return jsonify({"success": False})


if __name__ == "__main__":
    app.run(port=5000, debug=False)
