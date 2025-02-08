function fetchChartData() {
    fetch('/report/data/')  // เรียกข้อมูลจาก URL API
        .then(response => response.json())
        .then(data => {
            initChart(data);
        })
        .catch(error => console.error('Error fetching chart data:', error));
}

function initChart(chartData) {
    var ctx = document.getElementById('pieChart').getContext('2d');

    // แสดงข้อมูลไตรมาสที่ 1 เป็นค่าเริ่มต้น
    var currentQuarter = 'Q1';

    // สร้างกราฟ Pie Chart
    window.pieChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['อยู่ระหว่างการทำ', 'ทำเสร็จสิ้นแล้ว', 'รอการยืนยัน'],
            datasets: [{
                data: [
                    chartData[currentQuarter]['in_progress'],
                    chartData[currentQuarter]['completed'],
                    chartData[currentQuarter]['Waiting_confirmation']
                ],
                backgroundColor: ['#FF6384', '#36A2EB', '#FFCE56'],
                hoverBackgroundColor: ['#FF6384', '#36A2EB', '#FFCE56']
            }]
        },
        options: {
            responsive: false,
            maintainAspectRatio: false,
            plugins: {
                legend: { position: 'top' },
                title: { display: true, text: 'รายงานสถานะงาน - ไตรมาสที่ 1' }
            }
        }
    });

    // ล็อกขนาดกราฟ
    document.getElementById('pieChart').style.width = '300x';
    document.getElementById('pieChart').style.height = '300px';
}

// ฟังก์ชันเปลี่ยนกราฟตามไตรมาสที่เลือก
function updateChart() {
    var selectedQuarter = document.getElementById('quarterFilter').value;
    fetch('/report/data/')
        .then(response => response.json())
        .then(chartData => {
            pieChart.data.datasets[0].data = [
                chartData[selectedQuarter]['in_progress'],
                chartData[selectedQuarter]['completed'],
                chartData[selectedQuarter]['Waiting_confirmation']
            ];
            pieChart.options.plugins.title.text = 'รายงานสถานะงาน - ' + selectedQuarter;
            pieChart.update();
        })
        .catch(error => console.error('Error updating chart:', error));
}

function exportToExcel() {
    // ดึงข้อมูลจากกราฟ Chart.js
    var chartData = pieChart.data.datasets[0].data;
    var labels = pieChart.data.labels;
    
    // สร้างข้อมูลสำหรับ Excel
    var exportData = labels.map((label, index) => {
        return {
            'Category': label,
            'Value': chartData[index]
        };
    });

    // แปลงข้อมูลเป็น sheet
    var worksheet = XLSX.utils.json_to_sheet(exportData);
    var workbook = XLSX.utils.book_new();
    XLSX.utils.book_append_sheet(workbook, worksheet, "Report Data");

    // ดาวน์โหลดไฟล์ Excel
    XLSX.writeFile(workbook, "chart_data.xlsx");
}