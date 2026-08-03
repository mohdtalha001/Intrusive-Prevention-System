from flask import Flask, render_template, jsonify
from database import init_db, get_all_logs

app = Flask(__name__)

# DB Check on start
init_db()

@app.route('/')
def index():
    # Render Dashboard UI
    return render_template('index.html')

@app.route('/api/logs')
def api_logs():
    # Fetch latest 20 threat logs
    rows = get_all_logs(limit=20)
    logs_data = []
    
    for row in rows:
        logs_data.append({
            "id": row[0],
            "timestamp": row[1],
            "src_ip": row[2],
            "attack_type": row[3],
            "action": row[4]
        })
        
    return jsonify(logs_data)

if __name__ == '__main__':
    print("🚀 Web Dashboard starting at http://127.0.0.1:5000")
    app.run(debug=True, port=5000)