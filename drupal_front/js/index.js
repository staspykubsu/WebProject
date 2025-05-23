document.addEventListener('DOMContentLoaded', function () {
    var splide_reviews = new Splide('.splide', {
        perPage: 1,
        width: '100%',
        perMove: 1,
        gap: '2rem',
        autoplay: false,
        interval: 5000,
        type  : 'loop',
    });
    
    splide_reviews.mount();

    var clientsSlider1 = new Splide( '#clients-gallery-1', {
        type: "loop",
        width: "140%",
        perMove: 1,
        perPage: 14,
        gap: "1em",
        autoWidth: true,
        arrows: false,
        pagination: false,
        drag: false,
        autoplay: true,
        interval: 4000,
        speed: 1200,
        breakpoints: {
            780: {
                height: "100px",
            }
        }
    });
    clientsSlider1.mount();

$(function(){
    $(".formcarryForm").submit(function(e){
      e.preventDefault();
      var href = $(this).attr("action");
      
      $.ajax({
          type: "POST",
          url: href,
          data: new FormData(this),
          dataType: "json",
          processData: false,
          contentType: false,
          success: function(response){
            if(response.status == "success"){
                alert("We received your submission, thank you!");
            }
            else if(response.code === 422){
              alert("Field validation failed");
              $.each(response.errors, function(key) {
                $('[name="' + key + '"]').addClass('formcarry-field-error');
              });
            }
            else{
              alert("An error occured: " + response.message);
            }
          },
          error: function(jqXHR, textStatus){
            const errorObject = jqXHR.responseJSON
  
            alert("Request failed, " + errorObject.title + ": " + errorObject.message);
          },
          complete: function(){
            history.pushState({ formOpen: false }, '', '/');
            popupForm.style.display = 'none';
          }
      });
    });
  });
});

const startCard = document.getElementById("start-card");
const mainCard = document.getElementById("main-card");
const vipCard = document.getElementById("card-vip");

document.addEventListener("DOMContentLoaded", () => {
    vipCard.addEventListener("mouseover", () => {
        mainCard.style.transform = "scale(.9)";
    });
    vipCard.addEventListener("mouseout", () => {
        mainCard.style.transform = "scale(1)";
    });

    startCard.addEventListener("mouseover", () => {
        mainCard.style.transform = "scale(.9)";
    });
    startCard.addEventListener("mouseout", () => {
        mainCard.style.transform = "scale(1)";
    });
});


// Открытие/закрытие навбара на мобильных устройствах
$(document).ready(function() {
    $('#bars').click(function() {
        $('#mobile-menu-outter').toggle(); 
    });
});

// При клике на иконку стрелки вниз открывем меню выбора языка
document.getElementById("mobile-menu-icon").addEventListener("click", function(event) {
    const menu = document.getElementById("dropout-menu-outter");
    const arrowIcon = document.getElementById("mobile-menu-icon");
    
    menu.style.display = (menu.style.display === "block") ? "none" : "block";
    
    if (menu.style.display === "block") {
        arrowIcon.classList.remove("fa-chevron-down");
        arrowIcon.classList.add("fa-chevron-up");
    }
    else {
        arrowIcon.classList.remove("fa-chevron-up");
        arrowIcon.classList.add("fa-chevron-down");
    }
    
    event.stopPropagation();
});

// Закрываем меню, если кликнуть за пределами
document.addEventListener("click", function(event) {
    const menu = document.getElementById("dropout-menu-outter");
    const menuTrigger = document.getElementById("arrow-down");
    
    if (!menuTrigger.contains(event.target) && !menu.contains(event.target)) {
        menu.style.display = "none";

        const arrowIcon = document.getElementById("mobile-menu-icon");
        arrowIcon.classList.remove("fa-chevron-up");
        arrowIcon.classList.add("fa-chevron-down");
    }
});