(function ($) {
    "use strict";

    // Spinner
    var spinner = function () {
        setTimeout(function () {
            if ($('#spinner').length > 0) {
                $('#spinner').removeClass('show');
            }
        }, 1);
    };
    spinner();


    // Back to top button
    $(window).scroll(function () {
        if ($(this).scrollTop() > 300) {
            $('.back-to-top').fadeIn('slow');
        } else {
            $('.back-to-top').fadeOut('slow');
        }
    });
    $('.back-to-top').click(function () {
        $('html, body').animate({ scrollTop: 0 }, 1500, 'easeInOutExpo');
        return false;
    });


    // Sidebar Toggler
    $('.sidebar-toggler').click(function () {
        $('.sidebar, .content').toggleClass("open");
        return false;
    });


    // Progress Bar
    // Ensure elements with class 'pg-bar' exist if this feature is needed
    $('.pg-bar').waypoint(function () {
        $('.progress .progress-bar').each(function () {
            $(this).css("width", $(this).attr("aria-valuenow") + '%');
        });
    }, { offset: '80%' });


    // Calender
    // Ensure element with id 'calender' exists if this feature is needed
    $('#calender').datetimepicker({
        inline: true,
        format: 'L'
    });


    // Testimonials carousel
    // Ensure element with class 'testimonial-carousel' exists if this feature is needed
    $(".testimonial-carousel").owlCarousel({
        autoplay: true,
        smartSpeed: 1000,
        items: 1,
        dots: true,
        loop: true,
        nav: false
    });


    // Chart Global Color
    Chart.defaults.color = "#6C7293";
    Chart.defaults.borderColor = "#000000";

    // --- Chart Initializations with Checks ---

    // Worldwide Sales Chart
    var worldwideSalesCanvas = $("#worldwide-sales").get(0);
    if (worldwideSalesCanvas) { // Check if the canvas element exists
        var ctx1 = worldwideSalesCanvas.getContext("2d");
        var myChart1 = new Chart(ctx1, {
            type: "bar",
            data: {
                labels: ["2016", "2017", "2018", "2019", "2020", "2021", "2022"],
                datasets: [{
                    label: "USA",
                    data: [15, 30, 55, 65, 60, 80, 95],
                    backgroundColor: "rgba(235, 22, 22, .7)"
                },
                {
                    label: "UK",
                    data: [8, 35, 40, 60, 70, 55, 75],
                    backgroundColor: "rgba(235, 22, 22, .5)"
                },
                {
                    label: "AU",
                    data: [12, 25, 45, 55, 65, 70, 60],
                    backgroundColor: "rgba(235, 22, 22, .3)"
                }
                ]
            },
            options: {
                responsive: true
            }
        });
    } else {
        console.warn("Canvas element with id 'worldwide-sales' not found, skipping chart initialization.");
    }


    // Salse & Revenue Chart
    var salseRevenueCanvas = $("#salse-revenue").get(0);
     if (salseRevenueCanvas) { // Check if the canvas element exists
        var ctx2 = salseRevenueCanvas.getContext("2d");
        var myChart2 = new Chart(ctx2, {
            type: "line",
            data: {
                labels: ["2016", "2017", "2018", "2019", "2020", "2021", "2022"],
                datasets: [{
                    label: "Salse",
                    data: [15, 30, 55, 45, 70, 65, 85],
                    backgroundColor: "rgba(235, 22, 22, .7)",
                    fill: true
                },
                {
                    label: "Revenue",
                    data: [99, 135, 170, 130, 190, 180, 270],
                    backgroundColor: "rgba(235, 22, 22, .5)",
                    fill: true
                }
                ]
            },
            options: {
                responsive: true
            }
        });
     } else {
         console.warn("Canvas element with id 'salse-revenue' not found, skipping chart initialization.");
     }


    // Single Line Chart
    var lineChartCanvas = $("#line-chart").get(0);
     if (lineChartCanvas) { // Check if the canvas element exists
        var ctx3 = lineChartCanvas.getContext("2d");
        var myChart3 = new Chart(ctx3, {
            type: "line",
            data: {
                labels: [50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150],
                datasets: [{
                    label: "Salse",
                    fill: false,
                    backgroundColor: "rgba(235, 22, 22, .7)",
                    data: [7, 8, 8, 9, 9, 9, 10, 11, 14, 14, 15]
                }]
            },
            options: {
                responsive: true
            }
        });
     } else {
         console.warn("Canvas element with id 'line-chart' not found, skipping chart initialization.");
     }


    // Single Bar Chart
    var barChartCanvas = $("#bar-chart").get(0);
     if (barChartCanvas) { // Check if the canvas element exists
        var ctx4 = barChartCanvas.getContext("2d");
        var myChart4 = new Chart(ctx4, {
            type: "bar",
            data: {
                labels: ["Italy", "France", "Spain", "USA", "Argentina"],
                datasets: [{
                    backgroundColor: [
                        "rgba(235, 22, 22, .7)",
                        "rgba(235, 22, 22, .6)",
                        "rgba(235, 22, 22, .5)",
                        "rgba(235, 22, 22, .4)",
                        "rgba(235, 22, 22, .3)"
                    ],
                    data: [55, 49, 44, 24, 15]
                }]
            },
            options: {
                responsive: true
            }
        });
     } else {
         console.warn("Canvas element with id 'bar-chart' not found, skipping chart initialization.");
     }


    // piechart.js (DOMContentLoaded listener)
    // Note: This chart initialization is already inside a DOMContentLoaded listener
    // which is good practice. We still need to check if the canvas exists.
     document.addEventListener("DOMContentLoaded", function () {
         var pieChartCanvas = document.getElementById("pie-chart"); // Use native JS as it's in the original
          if (pieChartCanvas) { // Check if the canvas element exists
             var ctx5 = pieChartCanvas.getContext("2d");
             new Chart(ctx5, {
                 type: "pie",
                 data: {
                     labels: ["Italy", "France", "Spain", "USA", "Argentina"],
                     datasets: [{
                         data: [55, 49, 44, 24, 15]
                     }]
                 },
                 options: {
                     responsive: true,
                     plugins: {
                         legend: {
                             position: "bottom",
                             labels: {
                                 color: "#fff"
                             }
                         }
                     }
                 }
             });
          } else {
             console.warn("Canvas element with id 'pie-chart' not found, skipping chart initialization.");
         }
     });


    // Doughnut Chart
    var doughnutChartCanvas = $("#doughnut-chart").get(0);
     if (doughnutChartCanvas) { // Check if the canvas element exists
        var ctx6 = doughnutChartCanvas.getContext("2d");
        var myChart6 = new Chart(ctx6, {
            type: "doughnut",
            data: {
                labels: ["Italy", "France", "Spain", "USA", "Argentina"],
                datasets: [{
                    backgroundColor: [
                        "rgba(235, 22, 22, .7)",
                        "rgba(235, 22, 22, .6)",
                        "rgba(235, 22, 22, .5)",
                        "rgba(235, 22, 22, .4)",
                        "rgba(235, 22, 22, .3)"
                    ],
                    data: [55, 49, 44, 24, 15]
                }]
            },
            options: {
                responsive: true
            }
        });
     } else {
        console.warn("Canvas element with id 'doughnut-chart' not found, skipping chart initialization.");
     }


})(jQuery);