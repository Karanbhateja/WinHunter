function copyToClipboard(elementId, buttonElement) {
    const element = document.getElementById(elementId);
    let textToCopy = element.value || element.innerText;

    navigator.clipboard.writeText(textToCopy).then(() => {
        // Provide visual feedback
        const originalContent = buttonElement.innerHTML;
        buttonElement.innerHTML = `<i class="bi bi-check-lg"></i> Copied!`;
        buttonElement.classList.add('btn-success');
        buttonElement.classList.remove('btn-outline-secondary');
        
        // Revert back after 2 seconds
        setTimeout(() => {
            buttonElement.innerHTML = originalContent;
            buttonElement.classList.remove('btn-success');
            buttonElement.classList.add('btn-outline-secondary');
        }, 2000);
    }).catch(err => {
        console.error('Failed to copy text: ', err);
        // Provide error feedback
        const originalContent = buttonElement.innerHTML;
        buttonElement.innerHTML = `<i class="bi bi-x-lg"></i> Error`;
        buttonElement.classList.add('btn-danger');

        setTimeout(() => {
            buttonElement.innerHTML = originalContent;
            buttonElement.classList.remove('btn-danger');
        }, 2000);
    });
}