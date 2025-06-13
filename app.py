from flask import Flask, render_template, request
import numpy as np
import pickle

app = Flask(__name__)

# Load the trained model
model = pickle.load(open('model.pkl', 'rb'))

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # Get data from form
        rm = float(request.form['rm'])
        lstat = float(request.form['lstat'])
        ptratio = float(request.form['ptratio'])

        # Make prediction
        input_features = np.array([[rm, lstat, ptratio]])
        prediction = model.predict(input_features)[0]

        return render_template('index.html',
                               prediction_text=f"Predicted House Price: ${prediction * 1000:.2f}")
    except:
        return render_template('index.html', prediction_text="Invalid input. Please enter numeric values.")

if __name__ == "__main__":
    app.run(debug=True)
