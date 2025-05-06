// piechart.js
document.addEventListener('DOMContentLoaded', function () {
    const ctx = document.getElementById('pie-chart').getContext('2d');
    if (!ctx) {
        console.error('Canvas element with id "pie-chart" not found');
        return;
    }

    const pieChart = new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Absent', 'Present'],
            datasets: [{
                data: [3.5, 96.5], // 3.5% absent, 96.5% present based on overall attendance
                backgroundColor: [
                    '#FF4040', // Lighter shade of red
                    '#EB1616', // Primary red from CSS
                ],
                borderWidth: 1,
                borderColor: '#fff'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#fff'
                    }
                }
            }
        }
    });

    console.log('Pie chart initialized:', pieChart);
});