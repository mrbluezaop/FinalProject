// to get current year
function getYear() {
    var currentDate = new Date();
    var currentYear = currentDate.getFullYear();
    document.querySelector("#displayYear").innerHTML = currentYear;
}

getYear();



// slick slider
$('.chocolate_container').slick({
    infinite: true,
    center: true,
    slidesToShow: 3,
    slidesToScroll: 1,
    responsive: [{
            breakpoint: 991,
            settings: {
                slidesToShow: 2,
                slidesToScroll: 1
            }
        },
        {
            breakpoint: 576,
            settings: {
                slidesToShow: 1,
                slidesToScroll: 1
            }
        }

    ]
});
// popup.js

jQuery(document).ready(function($){
    // Open the pop-up when Buy Now button is clicked
    $('#buyNowButton').on('click', function(event){
        event.preventDefault();
        $('#buyPopup').show();
    });

    // Close the pop-up when the "ตกลง" button is clicked
    $('#confirmButton').on('click', function(){
        // Redirect to the next page (replace 'next_page.php' with the actual URL)
        window.location.href = 'next_page.php';
    });

    // Close the pop-up when the "ไม่" button is clicked
    $('#cancelButton').on('click', function(){
        $('#buyPopup').hide();
    });
});
