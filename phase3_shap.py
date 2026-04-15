import shap
import matplotlib.pyplot as plt

def generate_shap_plot(model, traffic_features, feature_names, save_path="outputs/shap_latest_alert.png"):
    # 1. Initialize the explainer (Using KernelExplainer or DeepExplainer depending on your DNN)
    explainer = shap.KernelExplainer(model.predict, shap.sample(traffic_features, 10))
    
    # 2. Calculate SHAP values for the specific anomalous packet window
    shap_values = explainer.shap_values(traffic_features)
    
    # 3. Generate the plot
    plt.figure()
    
    # If it's a binary classification (Normal vs DoS), we usually plot the first instance
    shap.summary_plot(shap_values, traffic_features, feature_names=feature_names, show=False)
    
    # 4. Save the plot for Streamlit to read
    plt.savefig(save_path, bbox_inches='tight')
    plt.close()