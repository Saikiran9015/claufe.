// Simple table search for brand/products
// SAI kiran shairing me th elive ocde
function filterTable(inputId, tableId) {
    const input = document.getElementById(inputId);
    const table = document.getElementById(tableId);
    if (!input || !table) return;

    const filter = input.value.toLowerCase();
    const rows = table.getElementsByTagName("tr");

    for (let i = 1; i < rows.length; i++) {
        const cells = rows[i].getElementsByTagName("td");
        let match = false;
        for (let c = 0; c < cells.length; c++) {
            if (cells[c].innerText.toLowerCase().indexOf(filter) > -1) {
                match = true;
                break;
            }
        }
        rows[i].style.display = match ? "" : "none";
    }
}

function confirmDelete(formId) {
    if (confirm("Delete this product?")) {
        document.getElementById(formId).submit();
    }
}
