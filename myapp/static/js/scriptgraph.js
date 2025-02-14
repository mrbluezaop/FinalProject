document.addEventListener("DOMContentLoaded", function() {
    document.querySelectorAll(".clickable-row").forEach(row => {
        row.addEventListener("click", function() {
            const hireID = this.getAttribute("data-hire-id");

            fetch(`/get_resource_data/?hire_id=${hireID}`)
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        console.error("Error: Resource not found");
                        return;
                    }
                    showChart(data);
                })
                .catch(error => console.error("Error fetching data:", error));
        });
    });
});

// ฟังก์ชันแสดงกราฟ
function showChart(data) {
    document.getElementById("chart-container").style.display = "block";
    
    const ctx = document.getElementById("resourceChart").getContext("2d");

    // 🔥 ตรวจสอบว่ามีกราฟเก่าและเป็น Object ของ Chart.js ก่อนทำลาย
    if (window.resourceChart instanceof Chart) {
        window.resourceChart.destroy();
    }

    // 🔹 สร้างกราฟใหม่
    window.resourceChart = new Chart(ctx, {
        type: "bar",
        data: {
            labels: ["Wood_P", "Paint_P", "Lighting_P", "Nail_P", "Table_P", "Chair_P"],
            datasets: [{
                label: "Predicted Usage",
                data: [data.Wood_P, data.Paint_P, data.Lighting_P, data.Nail_P, data.Table_P, data.Chair_P],
                backgroundColor: ["#4CAF50", "#2196F3", "#FF9800", "#9C27B0", "#FF5722", "#607D8B"]
            }]
        },
        options: {
            responsive: true,
            scales: {
                y: { beginAtZero: true }
            }
        }
    });
}
