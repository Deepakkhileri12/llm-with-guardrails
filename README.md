# Call LLMs with Guardrails
Llama Guardrails act as a security check that monitors everything from user input to the generated output, aiming to ensure the output is user-friendly, reliable, and safe.

## How to use it:
Before using this, you need to paste your Gemini API key into the `.env` file; then, you can run the project on your system by executing `app.py` with the help of `streamlit run app.py` command.

## 🛠️ Six guardrails components:
* Input Guardrails
* Context Guardrails
* Tool Guardrails
* Business Guardrails
* Human-in-the-loop Guardrails
* Output Guardrails


## 📂 Project Structure
```text
├── Guardrails/           # Security checks and call llms
├── UI/               # Dashboard UI components and frontend files
├── app.py            # Main application entry point
└── requirements.txt  # Project dependencies