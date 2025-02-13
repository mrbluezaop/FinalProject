window.showSaveModelPopup = function (predictId) {
    console.log("✅ Opening Save Model Popup for predictId:", predictId);

    // เรียก API เพื่อดึงค่าล่าสุดของ Prediction
    $.ajax({
        url: `/api/predictC/${predictId}/`,  // 🔹 แก้ URL ให้เป็น API ที่ใช้ดึงข้อมูล predict
        type: 'GET',
        dataType: 'json',
        success: function (predict) {
            console.log("✅ Received Predict Data:", predict);

            // ✅ ตรวจสอบข้อมูลที่ได้รับจาก API
            if (!predict || typeof predict !== "object" ||
                !("Paint" in predict) || !("Chair" in predict) ||
                !("Lighting" in predict) || !("Nail" in predict) ||
                !("Table" in predict)) {
                Swal.fire({
                    icon: "error",
                    title: "Error",
                    text: "Missing required fields in prediction response.",
                    confirmButtonText: "OK"
                });
                console.error("❌ Incomplete prediction data:", predict);
                return;
            }

            // ✅ ตั้งค่าข้อมูลฝั่ง Current Data
            document.getElementById("currentPaint").innerText = `${predict.Paint} Cans`;
            document.getElementById("currentChair").innerText = `${predict.Chair} Chairs`;
            document.getElementById("currentLighting").innerText = `${predict.Lighting} Bulbs`;
            document.getElementById("currentNail").innerText = `${predict.Nail} Boxes`;
            document.getElementById("currentTable").innerText = `${predict.Table} Tables`;
            console.log(predict)

            // ✅ เคลียร์ค่าฝั่ง New Data
            document.querySelectorAll(".popup-column input").forEach(input => {
                input.value = "";
            });

            // ✅ แสดง Popup
            modal.style.display = "flex";
        },
        error: function (xhr, status, error) {
            console.error("❌ Error fetching predict data:", error);
            Swal.fire({
                icon: "error",
                title: "Error",
                text: "ไม่สามารถดึงข้อมูลพยากรณ์ได้ กรุณาลองใหม่",
                confirmButtonText: "OK"
            });
        }
    });
};

saveBtn.addEventListener("click", function () {
    console.log("💾 Saving new model data...");

    const predictId = saveBtn.getAttribute("data-id"); // ดึง predictId จากปุ่ม Save
    if (!predictId) {
        console.error("❌ Missing predictId!");
        Swal.fire({
            icon: "error",
            title: "Error",
            text: "Predict ID is missing. Cannot proceed.",
            confirmButtonText: "OK"
        });
        return;
    }

    // ✅ เรียก API เพื่อดึงข้อมูลปัจจุบันของ Prediction
    $.ajax({
        url: `/api/predictC/${predictId}/`,
        type: 'GET',
        dataType: 'json',
        success: function (predict) {
            console.log("✅ Received Predict Data:", predict);

            // ✅ ตรวจสอบข้อมูลที่ได้รับจาก API
            if (!predict || typeof predict !== "object" ||
                !("Paint" in predict) || !("Chair" in predict) ||
                !("Lighting" in predict) || !("Nail" in predict) ||
                !("Table" in predict)) {
                Swal.fire({
                    icon: "error",
                    title: "Error",
                    text: "Missing required fields in prediction response.",
                    confirmButtonText: "OK"
                });
                console.error("❌ Incomplete prediction data:", predict);
                return;
            }

            // ✅ จัดเตรียมข้อมูลสำหรับบันทึก
            const newData = {
                "Predict_ID": predict.Predict_ID,
                "Width": predict.Width,
                "Length": predict.Length,
                "Height": predict.Height,
                "Job_type": predict.Type,
                "Budget": predict.Budget,
                "Wood_P": predict.Wood,
                "Paint_P": predict.Paint,
                "Lighting_P": predict.Lighting,
                "Nail_P": predict.Nail,
                "Table_P": predict.Table,
                "Chair_P": predict.Chair,
                "DateOfHire": predict.HireC_ID.Dateofhire,
                "Type": predict.HireC_ID.Type,
                "Location": predict.HireC_ID.Location,

                // ✅ ค่าที่ผู้ใช้แก้ไขใหม่
                "Wood": document.getElementById("newWood").value || "0",
                "Paint": document.getElementById("newPaint").value || "0",
                "Chair": document.getElementById("newChair").value || "0",
                "Lighting": document.getElementById("newLighting").value || "0",
                "Nail": document.getElementById("newNail").value || "0",
                "Table": document.getElementById("newTable").value || "0"
            };

            console.log("📤 Sending data to submit_success/:", newData);

            // ✅ ส่งข้อมูลไปยัง `/submit_success/`
            $.ajax({
                url: '/submit_success/',
                type: 'POST',
                data: JSON.stringify(newData),
                contentType: 'application/json',
                headers: { "X-CSRFToken": getCookie("csrftoken") },
                success: function (response) {
                    console.log("✅ Data successfully saved:", response);
                    Swal.fire({
                        icon: "success",
                        title: "Saved Successfully!",
                        text: "New model data has been saved.",
                        confirmButtonText: "OK"
                    });

                    modal.style.display = "none"; // ปิด Popup หลังจาก Save
                },
                error: function (xhr, status, error) {
                    console.error("❌ Error saving data:", error);
                    Swal.fire({
                        icon: "error",
                        title: "Save Failed!",
                        text: "An error occurred while saving. Please try again.",
                        confirmButtonText: "OK"
                    });
                }
            });
        },
        error: function (xhr, status, error) {
            console.error("❌ Error fetching prediction data:", error);
            Swal.fire({
                icon: "error",
                title: "Error",
                text: "Failed to retrieve prediction data. Please try again.",
                confirmButtonText: "OK"
            });
        }
    });
});

document.addEventListener("DOMContentLoaded", function () {
    console.log("✅ JavaScript Loaded!");

    // ✅ ดึงปุ่มทั้งหมดที่มี class "save-btn"
    document.querySelectorAll(".save-btn").forEach((saveBtn) => {
        saveBtn.addEventListener("click", function () {
            console.log("💾 Saving new model data...");

            // ✅ ดึง predictId จากปุ่มที่ถูกกด
            const predictId = saveBtn.getAttribute("data-id");
            if (!predictId || predictId === "N/A") {
                console.error("❌ Missing predictId!");
                Swal.fire({
                    icon: "error",
                    title: "Error",
                    text: "Predict ID is missing. Cannot proceed.",
                    confirmButtonText: "OK"
                });
                return;
            }
            console.log("✅ Predict ID:", predictId);

            // ✅ เรียก API เพื่อดึงข้อมูล Prediction
            $.ajax({
                url: `/api/predictC/${predictId}/`,
                type: 'GET',
                dataType: 'json',
                success: function (predict) {
                    console.log("✅ Received Predict Data:", predict);

                    // ✅ ตรวจสอบข้อมูล
                    if (!predict || typeof predict !== "object" ||
                        !("Paint" in predict) || !("Chair" in predict) ||
                        !("Lighting" in predict) || !("Nail" in predict) ||
                        !("Table" in predict)) {
                        Swal.fire({
                            icon: "error",
                            title: "Error",
                            text: "Missing required fields in prediction response.",
                            confirmButtonText: "OK"
                        });
                        console.error("❌ Incomplete prediction data:", predict);
                        return;
                    }

                    // ✅ จัดเตรียมข้อมูลสำหรับบันทึก
                    const newData = {
                        "Predict_ID": predict.Predict_ID,
                        "Width": predict.Width,
                        "Length": predict.Length,
                        "Height": predict.Height,
                        "Job_type": predict.Type,
                        "Budget": predict.Budget,
                        "Wood_P": predict.Wood,
                        "Paint_P": predict.Paint,
                        "Lighting_P": predict.Lighting,
                        "Nail_P": predict.Nail,
                        "Table_P": predict.Table,
                        "Chair_P": predict.Chair,
                        "DateOfHire": predict.HireC_ID.Dateofhire,
                        "Type": predict.HireC_ID.Type,
                        "Location": predict.HireC_ID.Location,

                        // ✅ ค่าที่ผู้ใช้แก้ไขใหม่
                        "Wood": document.getElementById("newWood")?.value || "0",
                        "Paint": document.getElementById("newPaint")?.value || "0",
                        "Chair": document.getElementById("newChair")?.value || "0",
                        "Lighting": document.getElementById("newLighting")?.value || "0",
                        "Nail": document.getElementById("newNail")?.value || "0",
                        "Table": document.getElementById("newTable")?.value || "0"
                    };

                    console.log("📤 Sending data to /submit_success/:", newData);

                    // ✅ ส่งข้อมูลไปยัง `/submit_success/`
                    $.ajax({
                        url: '/submit_success/',
                        type: 'POST',
                        data: JSON.stringify(newData),
                        contentType: 'application/json',
                        headers: { "X-CSRFToken": getCookie("csrftoken") },
                        success: function (response) {
                            console.log("✅ Data successfully saved:", response);
                            Swal.fire({
                                icon: "success",
                                title: "Saved Successfully!",
                                text: "New model data has been saved.",
                                confirmButtonText: "OK"
                            });

                            // ✅ ปิด Popup หลังจาก Save
                            document.getElementById("saveModelPopup").style.display = "none";
                        },
                        error: function (xhr, status, error) {
                            console.error("❌ Error saving data:", error);
                            Swal.fire({
                                icon: "error",
                                title: "Save Failed!",
                                text: "An error occurred while saving. Please try again.",
                                confirmButtonText: "OK"
                            });
                        }
                    });
                },
                error: function (xhr, status, error) {
                    console.error("❌ Error fetching prediction data:", error);
                    Swal.fire({
                        icon: "error",
                        title: "Error",
                        text: "Failed to retrieve prediction data. Please try again.",
                        confirmButtonText: "OK"
                    });
                }
            });
        });
    });
});
