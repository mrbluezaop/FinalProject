function openPopup(memberId) {
    fetch(`/get-member/${memberId}/`)
        .then(response => {
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            return response.json();
        })
        .then(data => {
            console.log(data); // ตรวจสอบข้อมูลที่ได้จาก API
            // เติมข้อมูลใน Popup
            document.getElementById('popup-id').value = data.id || '';
            document.getElementById('popup-username').value = data.username || '';
            document.getElementById('popup-password').value = data.password || '';
            document.getElementById('popup-firstname').value = data.firstname || ''; // เปลี่ยนจาก popup-fname
            document.getElementById('popup-lastname').value = data.lastname || '';  // เปลี่ยนจาก popup-lname
            document.getElementById('popup-email').value = data.email || '';
            document.getElementById('popup-phone').value = data.phone || '';        // เปลี่ยนจาก popup-tel
            document.getElementById('popup-address').value = data.address || '';
            document.getElementById('popup-birthday').value = data.birthday || '';  // เปลี่ยนจาก popup-bdate

            // แสดง Popup
            document.getElementById('popup').style.display = 'block';
            document.getElementById('overlay').style.display = 'block';
        })
        .catch(error => {
            console.error('Error fetching member data:', error);
            alert('Failed to fetch member data.');
        });
}

function closePopup() {
    // ปิด Popup และ Overlay
    document.getElementById('popup').style.display = 'none';
    document.getElementById('overlay').style.display = 'none';
}


function saveChanges() {
    console.log('Save button clicked');

    const memberId = document.getElementById('popup-id').value;
    const csrfToken = getCSRFToken();

    // ตรวจสอบว่า Member ID และ CSRF Token มีค่าหรือไม่
    if (!memberId || !csrfToken) {
        alert('Required fields are missing!');
        return;
    }

    // ตรวจสอบรหัสผ่าน
    const passwordInput = document.getElementById('popup-password');
    const passwordError = document.getElementById('password-error');
    const password = passwordInput.value;
    const passwordPattern = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;

    if (password && !passwordPattern.test(password)) {
        passwordError.style.display = 'block'; // แสดงข้อความแจ้งเตือน
        passwordError.textContent = "Password must be at least 8 characters long, include at least one uppercase letter, one number, and one special character.";
        passwordInput.focus();
        return;
    } else {
        passwordError.style.display = 'none'; // ซ่อนข้อความแจ้งเตือน
    }

    // ตรวจสอบเบอร์โทรศัพท์
    const phoneInput = document.getElementById('popup-phone');
    const phoneError = document.getElementById('phone-error');
    const phone = phoneInput.value;
    const phonePattern = /^\d{10}$/; // รูปแบบเบอร์โทรต้องเป็นตัวเลข 10 หลัก

    if (!phonePattern.test(phone)) {
        phoneError.style.display = 'block'; // แสดงข้อความแจ้งเตือน
        phoneError.textContent = "Phone number must be exactly 10 digits.";
        phoneInput.focus();
        return;
    } else {
        phoneError.style.display = 'none'; // ซ่อนข้อความแจ้งเตือน
    }

    // เก็บข้อมูลที่อัปเดต
    const updatedData = {
        Customer_ID: memberId,
        password: password, // ส่งรหัสผ่านแบบ plaintext
        firstname: document.getElementById('popup-firstname').value,
        lastname: document.getElementById('popup-lastname').value,
        email: document.getElementById('popup-email').value,
        phone: phone,
        address: document.getElementById('popup-address').value,
        birthday: document.getElementById('popup-birthday').value,
    };

    console.log('Updated Data:', updatedData);

    // ส่งข้อมูลไปยังเซิร์ฟเวอร์
    fetch('/update-member/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': csrfToken,
        },
        body: JSON.stringify(updatedData),
    })
        .then((response) => response.json())
        .then((result) => {
            console.log('Response:', result);
            if (result.status === 'success') {
                alert('Member updated successfully!');
                location.reload();
            } else {
                alert(`Error: ${result.message}`);
            }
        })
        .catch((error) => {
            console.error('Error updating member:', error);
            alert('An error occurred while updating the member.');
        });
}

function getCSRFToken() {
    const token = document.querySelector('meta[name="csrf-token"]');
    if (token) {
        console.log('CSRF Token:', token.getAttribute('content')); // ตรวจสอบค่าที่ดึงมา
        return token.getAttribute('content');
    } else {
        console.error('CSRF token not found.');
        return '';
    }
}

console.log('popup.js loaded'); // ตรวจสอบว่าไฟล์ถูกโหลด
console.log('getCSRFToken Type:', typeof getCSRFToken); // ควรแสดงเป็น "function"
console.log('CSRF Token:', getCSRFToken());

function deleteMember(memberId) {
    if (confirm("Are you sure you want to delete this member?")) {
        fetch(`/delete-member/${memberId}/`, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': '{{ csrf_token }}' // เพิ่ม CSRF Token
            }
        })
            .then(response => {
                if (response.ok) {
                    alert("Member deleted successfully!");
                    location.reload(); // โหลดหน้าใหม่เพื่ออัปเดตข้อมูล
                } else {
                    alert("Failed to delete the member.");
                }
            })
            .catch(error => console.error("Error:", error));
    }



}

function deleteHire(hireId) {
    const csrfToken = document.querySelector('[name=csrfmiddlewaretoken]')?.value || 
                      document.querySelector('meta[name="csrf-token"]')?.content;

    if (!csrfToken) {
        console.error("CSRF token not found. Make sure it's included in the template.");
        return; // หยุดการทำงานหากไม่มี CSRF Token
    }

    if (confirm("Are you sure you want to delete this hire record?")) {
        fetch(`/delete-hire/${hireId}/`, {
            method: 'DELETE',
            headers: {
                'X-CSRFToken': csrfToken, // ส่ง CSRF Token ไปยัง Backend
                'Content-Type': 'application/json',
            },
        })
        .then(response => {
            if (response.ok) {
                alert(`Hire ID ${hireId} deleted successfully!`);
                location.reload(); // โหลดหน้าใหม่
            } else {
                response.json().then(data => {
                    alert(data.error || "Failed to delete the hire record.");
                });
            }
        })
        .catch(error => console.error("Error:", error));
    }
}

function showHirePopup(hireId) {
    fetch(`/api/hire/${hireId}/`)
        .then(response => response.json())
        .then(data => {
            // ตั้งค่าข้อมูลใน Popup
            document.getElementById('hireId').value = data.Hire_ID;
            document.getElementById('width').value = data.Width;
            document.getElementById('length').value = data.Length;
            document.getElementById('height').value = data.Height;
            document.getElementById('type').value = data.Type;
            document.getElementById('budget').value = data.Budget;
            document.getElementById('location').value = data.Location;
            document.getElementById('status').value = data.Status;

            // แสดง Popup
            document.getElementById('hirePopup').style.display = 'flex';
        })
        .catch(error => {
            console.error("Error:", error);
            alert("Unable to fetch hire details. Please try again.");
        });
}

function closeHirePopup() {
    document.getElementById('hirePopup').style.display = 'none';
}

function updateHireStatus() {
    const hireId = document.getElementById('hireId').value;
    const newStatus = document.getElementById('status').value;

    fetch(`/update-hire-status/${hireId}/`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': document.querySelector('meta[name="csrf-token"]').content
        },
        body: JSON.stringify({ Status: newStatus })
    })
    .then(response => response.json())
    .then(data => {
        alert(data.message);
        closeHirePopup();
        location.reload(); // รีโหลดหน้าเพื่อแสดงสถานะที่อัปเดตแล้ว
    })
    .catch(error => {
        console.error("Error:", error);
        alert("Failed to update status.");
    });
}

