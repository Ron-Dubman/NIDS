import streamlit as st
import pandas as pd
import json
import re
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go
from collections import Counter
import os

st.set_page_config(
    page_title="IDS Alert Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

class IDSLogReader:
    def __init__(self, log_file="ids_alerts.log"):
        self.log_file = log_file
    
    def parse_log_line(self, line):
        #parse single line and extract info
        try:
            # search for log lines using regex
            json_match = re.search(r'\{.*\}', line)
            if json_match:
                alert_data = json.loads(json_match.group())
                log_parts = line.split(' - ')
                if len(log_parts) >= 3:
                    timestamp_str = log_parts[0]
                    level = log_parts[1]

                    #parse timestamp
                    try:
                        log_timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S,%f")
                    except ValueError:
                        log_timestamp = datetime.fromisoformat(alert_data.get('timestamp', ''))
                    
                    alert_data['log_level'] = level
                    alert_data['log_timestamp'] = log_timestamp
            return alert_data
        
        except (json.JSONDecodeError, ValueError, KeyError) as e:
            st.error(f"Error parsing log line: {e}")
            return None
        
    def read_alerts(self):
        #read & parse alerts from log file
        alerts = []
        if not os.path.exists(self.log_file):
            st.warning(f"Log file '{self.log_file}' not found. Please ensure your IDS is running and generating alerts.")
            return pd.DataFrame()
        try:
            with open(self.log_file, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line and '{' in line:  # Only process lines with JSON data
                        alert = self.parse_log_line(line)
                        if alert:
                            alerts.append(alert)

        except FileNotFoundError:
            st.error(f"Could not find log file: {self.log_file}")
            return pd.DataFrame()
        except Exception as e:
            st.error(f"Error reading log file: {e}")
            return pd.DataFrame()
        
        if alerts:
            df = pd.DataFrame(alerts)
            # Convert timestamp columns to datetime
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
            if 'log_timestamp' in df.columns:
                df['log_timestamp'] = pd.to_datetime(df['log_timestamp'])
            return df
        else:
            return pd.DataFrame()
        
def create_metrics_cards(df):
#Create metric cards for the dashboard
    if df.empty:
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Alerts", "0")
        with col2:
            st.metric("High Confidence Threats", "0")
        with col3:
            st.metric("Unique Source IPs", "0")
        with col4:
            st.metric("Threat Types", "0")
        return

    total_alerts = len(df)
    high_confidence = len(df[df['confidence'] > 0.8]) if 'confidence' in df.columns else 0
    unique_sources = df['source_ip'].nunique() if 'source_ip' in df.columns else 0
    threat_types = df['threat_type'].nunique() if 'threat_type' in df.columns else 0

    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Alerts", total_alerts)
    with col2:
        st.metric("High Confidence Threats", high_confidence)
    with col3:
        st.metric("Unique Source IPs", unique_sources)
    with col4:
        st.metric("Threat Types", threat_types)

def create_threat_distribution_chart(df):
#Create threat type distribution chart
    if df.empty or 'threat_type' not in df.columns:
        st.info("No threat type data available")
        return
    
    threat_counts = df['threat_type'].value_counts()
    
    fig = px.pie(
        values=threat_counts.values,
        names=threat_counts.index,
        title="Threat Type Distribution"
    )
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

def create_confidence_distribution(df):
    #Create confidence score histogram
    if df.empty or 'confidence' not in df.columns:
        st.info("No confidence data available")
        return
    
    fig = px.histogram(
        df,
        x='confidence',
        nbins=20,
        title="Confidence Score Distribution",
        labels={'confidence': 'Confidence Score', 'count': 'Number of Alerts'}
    )
    fig.add_vline(x=0.8, line_dash="dash", line_color="red", 
                annotation_text="High Confidence Threshold")
    fig.update_layout(height=400)
    st.plotly_chart(fig, use_container_width=True)

def main():
    st.title("🛡️ IDS Alert Dashboard")
    st.markdown("Real-time IDS alerts monitor")
    st.sidebar.header("Configuration")
    log_file = st.sidebar.text_input("Log File Path", value="ids_alerts.log")
    auto_refresh = st.sidebar.checkbox("Auto Refresh (30s)", value=False)

    if auto_refresh:
        st.sidebar.info("Dashboard will refresh every 30 seconds")
        import time
        time.sleep(30)
        st.rerun()

    if st.sidebar.button("🔄 Refresh Data"):
        st.rerun()

    log_reader = IDSLogReader(log_file)
    with st.spinner("Loading alerts..."):
        df = log_reader.read_alerts()

    if df.empty:
        st.warning("No alerts found. Make sure your IDS is running and the log file path is correct.")
        st.info("Expected log file format: ids_alerts.log")
        return
    # Display metrics
    st.header("📊 Overview")
    create_metrics_cards(df)
    
    # Time filter
    st.header("🕒 Time Filter")
    col1, col2 = st.columns(2)

    with col1:
        hours_back = st.selectbox(
            "Show alerts from last:",
            options=[1, 6, 12, 24, 48, 168],  # 1h, 6h, 12h, 1d, 2d, 1week
            format_func=lambda x: f"{x} hour{'s' if x > 1 else ''}" if x < 24 else f"{x//24} day{'s' if x//24 > 1 else ''}",
            index=3  # Default to 24 hours
        )
    
    # Filter data by time
    time_col = 'log_timestamp' if 'log_timestamp' in df.columns else 'timestamp'
    if time_col in df.columns:
        cutoff_time = datetime.now() - timedelta(hours=hours_back)
        df_filtered = df[df[time_col] >= cutoff_time]
        
        with col2:
            st.metric("Filtered Alerts", len(df_filtered))
    else:
        df_filtered = df
        with col2:
            st.metric("Total Alerts", len(df_filtered))

    #Analytics part
    st.header("📈 Analytics")

    col1 = st.columns(1)[0]
    
    with col1:
        create_threat_distribution_chart(df_filtered)
        create_confidence_distribution(df_filtered)

    #Deatailed alerts part
    st.header("🔍 Detailed Alerts")

    col1, col2, col3 = st.columns(3)
    with col1:
        if 'threat_type' in df_filtered.columns:
            selected_threats = st.multiselect(
                "Filter by Threat Type",
                options=df_filtered['threat_type'].unique(),
                default=df_filtered['threat_type'].unique()
            )
        else:
            selected_threats = []
    with col2:
        if 'log_level' in df_filtered.columns:
            selected_levels = st.multiselect(
                "Filter by Log Level",
                options=df_filtered['log_level'].unique(),
                default=df_filtered['log_level'].unique()
            )
        else:
            selected_levels = []
    
    with col3:
        min_confidence = st.slider(
            "Minimum Confidence",
            min_value=0.0,
            max_value=1.0,
            value=0.0,
            step=0.1
        )

    #Apply selected filters:
    df_table = df_filtered.copy()
    if selected_threats and 'threat_type' in df_table.columns:
        df_table = df_table[df_table['threat_type'].isin(selected_threats)]
    if selected_levels and 'log_level' in df_table.columns:
        df_table = df_table[df_table['log_level'].isin(selected_levels)]
    if 'confidence' in df_table.columns:
        df_table = df_table[df_table['confidence'] >= min_confidence]
    
    #Display table
    if not df_table.empty:
        # Select columns to display
        display_columns = []
        available_columns = df_table.columns.tolist()

        # Prioritize important columns
        priority_columns = ['log_timestamp', 'threat_type', 'source_ip', 
                        'destination_ip', 'confidence', 'log_level']
        
        for col in priority_columns:
            if col in available_columns:
                display_columns.append(col)
        
        # Add remaining columns
        for col in available_columns:
            if col not in display_columns:
                display_columns.append(col)
        
        # Format the dataframe for display
        df_display = df_table[display_columns].copy()

        time_col = 'log_timestamp' if 'log_timestamp' in df_display.columns else 'timestamp'
        if time_col in df_display.columns:
            df_display = df_display.sort_values(time_col, ascending=False)
        
        st.dataframe(
            df_display,
            use_container_width=True,
            height=400
        )

        # Export functionality
        csv = df_table.to_csv(index=False)
        st.download_button(
            label="📥 Download Filtered Alerts as CSV",
            data=csv,
            file_name=f"ids_alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    else:
        st.info("No alerts match the current filters.")
    
if __name__ == "__main__":
    main()





