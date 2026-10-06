import streamlit as st
from Guardrails.guarded_pipeline import run_guardrails_pipeline

def implement_chatbot():
    col1, col2 = st.columns([7, 1])
    with col1:
        user_input = st.text_input(
                "Label",
                label_visibility="collapsed",
                placeholder="Ask your question here...",
            )

    with col2:
        user_btn = st.button("Send")
        
    if user_btn and user_input:
        st.write(f"You asked: {user_input}")
    
        with st.spinner("AI is thinking and running guardrails..."):
            response = run_guardrails_pipeline(
            user_input, system_prompt="You are a helpful assistant."
        )

        st.write(f"AI Response: {response}")