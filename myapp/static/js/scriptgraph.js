document.addEventListener("DOMContentLoaded", function() {
    updateChart();
});

function updateChart() {
    let quarter = document.getElementById("quarterFilter").value;

    fetch(`/api/get_hire_data/?quarter=${quarter}`)
        .then(response => response.json())
        .then(data => {
            console.log("📌 API Response:", data);  // เช็คค่าที่ได้จาก API
            renderTable(data.hire);
        })
        .catch(error => console.error("🚨 Error fetching data:", error));
}

function renderTable(hire) {
    let container = document.getElementById("reportContainer");
    container.innerHTML = ""; // เคลียร์ข้อมูลก่อนหน้า

    if (hire.length === 0) {
        container.innerHTML = "<p>❌ ไม่มีข้อมูลสำหรับไตรมาสที่เลือก</p>";
        return;
    }

    let table = document.createElement("table");
    table.border = "1";
    let thead = table.createTHead();
    let row = thead.insertRow();

    let headers = ["ID", "Type", "Budget", "Location", "Date of Hire", "Status"];
    headers.forEach(header => {
        let th = document.createElement("th");
        th.innerText = header;
        row.appendChild(th);
    });

    let tbody = table.createTBody();

    hire.forEach(item => {
        let row = tbody.insertRow();
        row.insertCell(0).innerText = item.Hire_ID;
        row.insertCell(1).innerText = item.Type;
        row.insertCell(2).innerText = item.Budget;
        row.insertCell(3).innerText = item.Location;
        row.insertCell(4).innerText = new Date(item.Dateofhire).toLocaleDateString();
        row.insertCell(5).innerText = item.Status;
    });

    container.appendChild(table);
}
