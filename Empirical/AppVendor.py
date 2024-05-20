from flask import Flask, jsonify, request
import requests

app = Flask(__name__)

routing_table = {}

@app.route('/', methods=['POST'])
def main():
    params = request.get_json()
    response = requests.post(params["dst"], 
                             headers={"Content-Type": "application/json"}, 
                             data=params)
    return jsonify(response.json())

if __name__ == '__main__':
    app.run(debug=True)
