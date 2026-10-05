/* =========================================================
   TraceMail AI - Dashboard Module
   Handles dashboard interactions and visual updates
   ========================================================= */

document.addEventListener("DOMContentLoaded", function () {

    console.log("TraceMail AI dashboard module loaded.");

    // ---------------------------------------------------------
    // File upload
    // ---------------------------------------------------------

    const fileInput = document.querySelector(
        'input[type="file"]'
    );

    const uploadForm = document.querySelector(
        'form'
    );

    if (fileInput) {

        fileInput.addEventListener(
            "change",
            function () {

                if (!this.files || this.files.length === 0) {
                    return;
                }

                const file = this.files[0];

                console.log(
                    "Selected email:",
                    file.name
                );

                // Basic extension check
                if (
                    !file.name
                        .toLowerCase()
                        .endsWith(".eml")
                ) {

                    alert(
                        "Please select a valid .eml email file."
                    );

                    this.value = "";
                    return;
                }

                // Update upload label if available
                const fileNameElement =
                    document.querySelector(
                        "[data-file-name]"
                    );

                if (fileNameElement) {
                    fileNameElement.textContent =
                        file.name;
                }

            }
        );
    }


    // ---------------------------------------------------------
    // Form submission
    // ---------------------------------------------------------

    if (uploadForm) {

        uploadForm.addEventListener(
            "submit",
            function () {

                const submitButton =
                    uploadForm.querySelector(
                        'button[type="submit"]'
                    );

                if (submitButton) {

                    submitButton.disabled = true;

                    const originalText =
                        submitButton.textContent;

                    submitButton.dataset.originalText =
                        originalText;

                    submitButton.textContent =
                        "ANALYZING EMAIL...";

                }

            }
        );
    }


    // ---------------------------------------------------------
    // Smooth scrolling for internal links
    // ---------------------------------------------------------

    const internalLinks =
        document.querySelectorAll(
            'a[href^="#"]'
        );

    internalLinks.forEach(function (link) {

        link.addEventListener(
            "click",
            function (event) {

                const targetID =
                    this.getAttribute("href");

                if (
                    !targetID ||
                    targetID === "#"
                ) {
                    return;
                }

                const target =
                    document.querySelector(
                        targetID
                    );

                if (target) {

                    event.preventDefault();

                    target.scrollIntoView({
                        behavior: "smooth",
                        block: "start"
                    });

                }

            }
        );

    });


    // ---------------------------------------------------------
    // Evidence row highlighting
    // ---------------------------------------------------------

    const evidenceRows =
        document.querySelectorAll(
            ".evidence-row"
        );

    evidenceRows.forEach(function (row) {

        row.addEventListener(
            "mouseenter",
            function () {
                this.classList.add(
                    "evidence-active"
                );
            }
        );

        row.addEventListener(
            "mouseleave",
            function () {
                this.classList.remove(
                    "evidence-active"
                );
            }
        );

    });


    // ---------------------------------------------------------
    // Copy-to-clipboard buttons
    // ---------------------------------------------------------

    const copyButtons =
        document.querySelectorAll(
            "[data-copy]"
        );

    copyButtons.forEach(function (button) {

        button.addEventListener(
            "click",
            async function () {

                const selector =
                    this.getAttribute(
                        "data-copy"
                    );

                if (!selector) {
                    return;
                }

                const element =
                    document.querySelector(
                        selector
                    );

                if (!element) {
                    return;
                }

                try {

                    await navigator.clipboard.writeText(
                        element.textContent.trim()
                    );

                    const originalText =
                        this.textContent;

                    this.textContent =
                        "COPIED";

                    setTimeout(function () {

                        button.textContent =
                            originalText;

                    }, 1200);

                } catch (error) {

                    console.error(
                        "Copy failed:",
                        error
                    );

                }

            }
        );

    });


    // ---------------------------------------------------------
    // Dashboard section observer
    // ---------------------------------------------------------

    const sections =
        document.querySelectorAll(
            ".panel, .architecture-module"
        );

    if ("IntersectionObserver" in window) {

        const observer =
            new IntersectionObserver(
                function (entries) {

                    entries.forEach(function (entry) {

                        if (entry.isIntersecting) {

                            entry.target.classList.add(
                                "section-visible"
                            );

                        }

                    });

                },
                {
                    threshold: 0.08
                }
            );

        sections.forEach(function (section) {

            observer.observe(section);

        });

    }


    // ---------------------------------------------------------
    // Console information
    // ---------------------------------------------------------

    console.log(
        "TraceMail AI dashboard initialized."
    );

});