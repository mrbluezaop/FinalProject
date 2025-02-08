$(document).ready(function () {
    let usernameValid = false;
    let emailValid = false;

    function toggleSubmitButton() {
        if (usernameValid && emailValid) {
            $('#submitButton').prop('disabled', false);
        } else {
            $('#submitButton').prop('disabled', true);
        }
    }

    // Save form data to sessionStorage
    function saveFormData() {
        const formData = {};
        $('#registerForm').find('input, textarea, select').each(function () {
            formData[$(this).attr('name')] = $(this).val();
        });
        sessionStorage.setItem('registerFormData', JSON.stringify(formData));
    }

    // Restore form data from sessionStorage
    function restoreFormData() {
        const savedData = sessionStorage.getItem('registerFormData');
        if (savedData) {
            const formData = JSON.parse(savedData);
            for (const name in formData) {
                $(`[name="${name}"]`).val(formData[name]);
            }
        }
    }

    // Restore form data when the page is loaded
    restoreFormData();

    // Save form data on input change
    $('#registerForm').on('input', saveFormData);

    // Add focus/blur for Username help text
    $('#id_Username').on('focus', function () {
        $('#usernameHelp').show();
    }).on('blur', function () {
        $('#usernameHelp').hide();
    });

    // ตรวจสอบ Username ซ้ำ
    $('#id_Username').on('input', function () {
        const username = $(this).val();
        if (username) {
            $.get('/check-duplicate/', { field: 'Username', value: username }, function (data) {
                $('#username-check').text(data.message).css('color', data.duplicate ? 'red' : 'green');
                usernameValid = !data.duplicate;
                toggleSubmitButton();
            });
        } else {
            $('#username-check').text('');
            usernameValid = false;
            toggleSubmitButton();
        }
    });

    // Add focus/blur for Email help text
    $('#id_Email').on('focus', function () {
        $('#emailHelp').show();
    }).on('blur', function () {
        $('#emailHelp').hide();
    });

    // ตรวจสอบ Email ซ้ำ
    $('#id_Email').on('input', function () {
        const email = $(this).val();
        if (email) {
            $.get('/check-duplicate/', { field: 'Email', value: email }, function (data) {
                $('#email-check').text(data.message).css('color', data.duplicate ? 'red' : 'green');
                emailValid = !data.duplicate;
                toggleSubmitButton();
            });
        } else {
            $('#email-check').text('');
            emailValid = false;
            toggleSubmitButton();
        }
    });

    $(document).ready(function () {
        // Show help text when Phone field is focused
        $('#id_Phone').on('focus', function () {
            $('#phoneHelp').show();
        });

        // Hide help text when Phone field loses focus
        $('#id_Phone').on('blur', function () {
            $('#phoneHelp').hide();
        });
    });

    $(document).ready(function () {
        // Show help text when Password field is focused
        $('#id_Password').on('focus', function () {
            $('#passwordHelp').show();
        });

        // Hide help text when Password field loses focus
        $('#id_Password').on('blur', function () {
            $('#passwordHelp').hide();
        });
    });
});
