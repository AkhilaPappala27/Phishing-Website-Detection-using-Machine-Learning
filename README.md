# 🔐 Phishing Website Detection using Machine Learning

## 📌 Overview

This project detects whether a website is **Phishing** or **Legitimate** using Machine Learning.
It uses 30 engineered features extracted from URL, domain, and webpage content.

---

## 🚀 Features

* URL-based feature extraction
* Domain-based analysis (WHOIS, DNS)
* HTML & JavaScript behavior detection
* Real-time prediction from user input
* Random Forest model with ~96% accuracy

---

## 🧠 Model Details

* Algorithm: Random Forest Classifier
* Accuracy: ~97%
* Labels:

  * `1` → Legitimate
  * `-1` → Phishing

---

## 📊 Dataset Description

The dataset consists of **30 features** used to detect phishing websites, categorized as:

### 🔹 Address Bar Based Features

* IP Address usage
* URL Length
* URL Shortening Service
* @ Symbol in URL
* Double Slash Redirecting
* Prefix/Suffix (-) in Domain
* Subdomain Count
* HTTPS Usage
* Domain Registration Length
* Favicon
* Port
* HTTPS Token

---

### 🔹 Abnormal Based Features

* Request URL
* URL of Anchor
* Links in Tags
* Server Form Handler (SFH)
* Submitting to Email
* Abnormal URL

---

### 🔹 HTML & JavaScript Features

* Redirect Count
* onMouseOver Event
* Right Click Disabled
* Popup Window
* IFrame Usage

---

### 🔹 Domain Based Features

* Age of Domain
* DNS Record
* Web Traffic
* Page Rank
* Google Index
* Links Pointing to Page
* Statistical Report

---

## ⚙️ How It Works

User provides a URL → Features are extracted → Model predicts → Output is displayed

---

## 📂 Project Structure

```text
.
├── datasets/
│   ├── training_dataset.csv
│   └── sample_urls.csv
│
├── src/
│   ├── train_model.py
│   └── predict.py
│
├── models/
│   ├── phishing_model.pkl
│   └── columns.pkl
│
├── Phishing_Detection.ipynb
├── README.md
```

---

## 🚀 How to Run

### 1️⃣ Train the model

```bash
python src/train_model.py
```

### 2️⃣ Predict from URL

```bash
python src/predict.py
```

Enter a URL:

```
https://example.com
```

---

## 📊 Example Output

```
Enter URL: https://google.com
Prediction: Legitimate Website
```

---

## ⚠️ Limitations

* Model is based on URL and domain features
* May misclassify phishing pages hosted on legitimate domains
* Some features depend on external services (WHOIS, DNS)

---

## ⭐ Future Improvements

* Add content-based detection
* Build web interface
* Improve feature robustness
