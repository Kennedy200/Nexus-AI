setTimeout(() => {
    const dropZone = document.getElementById('drop-zone');
    const fileInput = document.getElementById('file-input');
    const btnBrowse = document.getElementById('btn-browse');
    const btnReplace = document.getElementById('btn-replace-file');

    const stateDefault = document.getElementById('state-default');
    const stateLoading = document.getElementById('state-loading');
    const stateSuccess = document.getElementById('state-success');

    const uploadingFilename = document.getElementById('uploading-filename');
    const previewFilename = document.getElementById('preview-filename');
    const previewFileIcon = document.getElementById('preview-file-icon');

    // State Switcher Function
    function setViewState(stateName) {
        stateDefault.classList.add('hidden');
        stateLoading.classList.add('hidden');
        stateSuccess.classList.add('hidden');

        if (stateName === 'default') stateDefault.classList.remove('hidden');
        if (stateName === 'loading') stateLoading.classList.remove('hidden');
        if (stateName === 'success') stateSuccess.classList.remove('hidden');
    }

    // Trigger file picker
    btnBrowse.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.click();
    });

    // Reset back to default view when "Replace" is clicked
    btnReplace.addEventListener('click', (e) => {
        e.stopPropagation();
        fileInput.value = ''; // Clear file
        setViewState('default');
    });

    // Drag and Drop styling
    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.add('dragover');
        });
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            dropZone.classList.remove('dragover');
        });
    });

    // Handle Dropped Files
    dropZone.addEventListener('drop', (e) => {
        const files = e.dataTransfer.files;
        if (files.length > 0) processFile(files[0]);
    });

    // Handle Selected Files via Input
    fileInput.addEventListener('change', () => {
        if (fileInput.files.length > 0) processFile(fileInput.files[0]);
    });

    async function processFile(file) {
        // 1. Switch to Loading View inside the box
        uploadingFilename.innerText = file.name;
        setViewState('loading');

        try {
            // 2. Call Backend API connector
            await NexusAPI.uploadLog(file);

            // 3. Set File Icon dynamically based on extension
            if (file.name.endsWith('.csv')) {
                previewFileIcon.className = "fa-solid fa-file-csv";
            } else if (file.name.endsWith('.log')) {
                previewFileIcon.className = "fa-solid fa-file-lines";
            } else {
                previewFileIcon.className = "fa-solid fa-file-code";
            }

            // 4. Update Success View details
            previewFilename.innerText = file.name;

            // Simulated upload delay for realistic feel
            setTimeout(() => {
                setViewState('success');
            }, 1200);

        } catch (error) {
            alert('Upload failed. Returning to default view.');
            setViewState('default');
        }
    }
}, 100);