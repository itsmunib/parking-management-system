// Entry receipt generation
document.getElementById('entryForm')?.addEventListener('submit', function (e) {
  e.preventDefault();

  const numberPlate = document.getElementById('number_plate').value || 'Unknown';
  const entryTime = new Date().toLocaleString();

  const receiptContent = `
    <div style="text-align: center; font-family: Arial, sans-serif; padding: 20px;">
      <h2>Parking System</h2>
      <h4>Entry Receipt</h4>
      <p><strong>Vehicle Number:</strong> ${numberPlate}</p>
      <p><strong>Entry Time:</strong> ${entryTime}</p>
    </div>
  `;

  const element = document.createElement('div');
  element.innerHTML = receiptContent;
  html2pdf()
    .from(element)
    .save(`entry_${numberPlate}_${Date.now()}.pdf`)
    .then(() => {
      e.target.submit();
    })
    .catch(err => {
      console.error('PDF generation failed:', err);
      e.target.submit();
    });
});

// Exit modal and receipt
let currentEntryId;

function showExitModal(id, numberPlate, entryTime, ownerName, phone, category, pricingType, price) {
  try {
    currentEntryId = id;
    document.getElementById('modal_number_plate').textContent = numberPlate || 'N/A';
    document.getElementById('modal_owner_name').textContent = ownerName || 'N/A';
    document.getElementById('modal_phone').textContent = phone || 'N/A';
    document.getElementById('modal_category').textContent = category || 'N/A';
    document.getElementById('modal_entry_time').textContent = entryTime ? new Date(entryTime).toLocaleString() : 'N/A';

    const entryDate = entryTime ? new Date(entryTime) : new Date();
    const exitDate = new Date();
    let cost = 0;
    if (pricingType === 'hourly') {
      const hours = Math.ceil((exitDate - entryDate) / (1000 * 60 * 60));
      cost = hours * (price || 0);
    } else {
      cost = price || 0;
    }
    document.getElementById('modal_cost').textContent = cost.toFixed(2);

    new bootstrap.Modal(document.getElementById('exitModal')).show();
  } catch (err) {
    console.error('Error in showExitModal:', err);
  }
}

function toggleExitButton() {
  try {
    const paidCheckbox = document.getElementById('paid');
    const exitButton = document.getElementById('exitButton');
    exitButton.disabled = !paidCheckbox.checked;
  } catch (err) {
    console.error('Error in toggleExitButton:', err);
  }
}

function submitExit() {
  try {
    const numberPlate = document.getElementById('modal_number_plate').textContent || 'Unknown';
    const entryTime = document.getElementById('modal_entry_time').textContent || 'N/A';
    const cost = document.getElementById('modal_cost').textContent || '0.00';
    const exitTime = new Date().toLocaleString();
    const duration = entryTime !== 'N/A' ? Math.ceil((new Date() - new Date(entryTime)) / (1000 * 60 * 60)) : 0;

    const receiptContent = `
      <div style="text-align: center; font-family: Arial, sans-serif; padding: 20px;">
        <h2>Parking System</h2>
        <h4>Exit Receipt</h4>
        <p><strong>Vehicle Number:</strong> ${numberPlate}</p>
        <p><strong>Entry Time:</strong> ${entryTime}</p>
        <p><strong>Exit Time:</strong> ${exitTime}</p>
        <p><strong>Duration:</strong> ${duration} hour(s)</p>
        <p><strong>Total Cost:</strong> $${cost}</p>
      </div>
    `;

    const element = document.createElement('div');
    element.innerHTML = receiptContent;
    html2pdf()
      .from(element)
      .save(`exit_${numberPlate}_${Date.now()}.pdf`)
      .then(() => {
        fetch('/exit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ entry_id: currentEntryId }),
        }).then(() => {
          window.location.href = '/dashboard';
        }).catch(err => {
          console.error('Fetch error:', err);
        });
      })
      .catch(err => {
        console.error('PDF generation failed:', err);
      });
  } catch (err) {
    console.error('Error in submitExit:', err);
  }
}