function showHirePopup(hireId) {
    fetch(`/api/hire/${hireId}/`)
        .then(response => response.json())
        .then(data => {
            // ✅ ตั้งค่าข้อมูลใน Popup
            document.getElementById('hireId').value = data.Hire_ID;
            document.getElementById('width').value = data.Width;
            document.getElementById('length').value = data.Length;
            document.getElementById('height').value = data.Height;
            document.getElementById('type').value = data.Type;
            document.getElementById('budget').value = data.Budget;
            document.getElementById('location').value = data.Location;
            document.getElementById('status').value = data.Status;

            // ✅ แสดง Popup
            document.getElementById('hirePopup').style.display = 'flex';

            // ✅ เรียก API prediction (POST) และส่งผลลัพธ์ไปบันทึก
            predictHire(data.Width, data.Length, data.Height, data.Type, data.Budget, data.Hire_ID);
        })
        .catch(error => {
            console.error("Error:", error);
            alert("Unable to fetch hire details. Please try again.");
        });
}

function predictHire(width, length, height, job_type, budget, hireId) {
    fetch("/api/prediction/", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken")  // ✅ ใช้ CSRF Token ถ้า Django ใช้ CSRF Protection
        },
        body: JSON.stringify({
            width: width,
            length: length,
            height: height,
            type: job_type,
            budget: budget
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.error) {
            alert("Prediction Error: " + data.error);
            return;
        }

        // ✅ แสดงผลลัพธ์ใน Popup
        document.getElementById('paintResult').innerText = data.Paint;
        document.getElementById('chairResult').innerText = data.Chair;
        document.getElementById('lightingResult').innerText = data.Lighting;
        document.getElementById('nailResult').innerText = data.Nail;
        document.getElementById('tableResult').innerText = data.Table;

        // ✅ ส่งผลลัพธ์ไปยัง API บันทึกข้อมูล
        savePredictHire(width, length, height, job_type, budget, data.Paint, data.Chair, data.Lighting, data.Nail, data.Table, hireId);
    })
    .catch(error => {
        console.error("Error:", error);
        alert("Unable to get prediction results. Please try again.");
    });
}

function savePredictHire(width, length, height, job_type, budget, paint, chair, lighting, nail, table, hireId) {
    fetch("/api/SavePredictHire/", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": getCookie("csrftoken")
        },
        body: JSON.stringify({
            width: width,
            length: length,
            height: height,
            type: job_type,
            budget: budget,
            paint: paint,
            chair: chair,
            lighting: lighting,
            nail: nail,
            table: table,
            hire_id: hireId
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert("Prediction Data " + data.status + " successfully!");
            document.getElementById('paintResult').innerText = data.Paint;
            document.getElementById('chairResult').innerText = data.Chair;
            document.getElementById('lightingResult').innerText = data.Lighting;
            document.getElementById('nailResult').innerText = data.Nail;
            document.getElementById('tableResult').innerText = data.Table;
        } else {
            alert("Error retrieving prediction: " + data.error);
        }
    })
    .catch(error => {
        console.error("Error:", error);
        alert("Unable to retrieve prediction data. Please try again.");
    });
}



// ✅ ฟังก์ชันดึง CSRF Token
function getCookie(name) {
    var cookieValue = null;
    if (document.cookie && document.cookie !== '') {
        var cookies = document.cookie.split(';');
        for (var i = 0; i < cookies.length; i++) {
            var cookie = cookies[i].trim();
            if (cookie.substring(0, name.length + 1) === (name + '=')) {
                cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                break;
            }
        }
    }
    return cookieValue;
}
