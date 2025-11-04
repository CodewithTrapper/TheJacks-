document.addEventListener("DOMContentLoaded", () => {

    const registerForm = document.getElementById("registerForm");
    if (registerForm) {
        registerForm.addEventListener("submit", (r) => {
            r.preventDefault();
            const username = document.getElementById("username").value.trim();
            const email = document.getElementById("email").value.trim();
            const password = document.getElementById("password").value.trim();
            const users = JSON.parse(localStorage.getItem("users")) || [];
            const userExists = users.find((user) => user.email === email);
            if (userExists) {
                alert("This email is already registered. Please sign in.");
                return;
            }
            const newUser = { username, email, password, role: email.includes("admin") ? "admin" : "user" };
            users.push(newUser);
            localStorage.setItem("users", JSON.stringify(users));
            alert("Registration successful! You can now sign in.");
            window.location.href = "login.html";
        });
    }

    const loginForm = document.querySelector("#loginForm");
    if (loginForm) {
        const savedEmail = localStorage.getItem("rememberedEmail");
        const savedPassword = localStorage.getItem("rememberedPassword");
        if (savedEmail) document.getElementById("loginEmail").value = savedEmail;
        if (savedPassword) document.getElementById("loginPassword").value = savedPassword;
        if (savedEmail || savedPassword) {
            const rememberCheckbox = document.querySelector("#remember");
            if (rememberCheckbox) rememberCheckbox.checked = true;
        }
        loginForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const email = document.getElementById("loginEmail").value.trim();
            const password = document.getElementById("loginPassword").value.trim();
            const users = JSON.parse(localStorage.getItem("users")) || [];
            const validUser = users.find(
                (user) => user.email === email && user.password === password
            );
            if (!validUser) {
                alert("Incorrect email or password.");
                return;
            }
            const rememberCheckbox = document.querySelector("#remember");
            if (rememberCheckbox && rememberCheckbox.checked) {
                localStorage.setItem("rememberedEmail", email);
                localStorage.setItem("rememberedPassword", password);
            } else {
                localStorage.removeItem("rememberedEmail");
                localStorage.removeItem("rememberedPassword");
            }
            sessionStorage.setItem("currentUser", JSON.stringify(validUser));
            window.location.href = "user-dashboard.html";
        });
    }

    const logoutBtn = document.getElementById("logoutbtn");
    if (logoutBtn) {
        logoutBtn.addEventListener("click", () => {
            sessionStorage.removeItem("currentUser");
            window.location.href = "login.html";
        });
    }

    const bookingForm = document.querySelector(".booking-card");
    if (bookingForm) {
        bookingForm.addEventListener("submit", (e) => {
            e.preventDefault();
            const checkin = document.querySelector("#checkin").value;
            const checkout = document.querySelector("#checkout").value;
            const guests = document.querySelector("#guests").value;
            const roomType = document.querySelector("#roomType").value;
            if (!checkin || !checkout) {
                alert("Select check-in and check-out");
                return;
            }
            const start = new Date(checkin);
            const end = new Date(checkout);
            if (end <= start) {
                alert("Checkout must be later.");
                return;
            }
            const diff = Math.ceil((end - start) / (1000 * 60 * 60 * 24));
            const bookingData = {
                checkin,
                checkout,
                nights: diff,
                guests,
                roomType,
            };
            localStorage.setItem("bookingInfo", JSON.stringify(bookingData));
            alert("Booking saved!");
        });
    }


    const checkin = document.getElementById("checkin");
    const checkout = document.getElementById("checkout");
    const roomType = document.getElementById("roomType");
    const totalPriceText = document.getElementById("totalPrice");
    const priceValue = document.getElementById("priceValue");
    const prices = {
        standard: 6000,
        deluxe: 10000,
        suite: 15000
    };
    function calculateTotal() {
        if (!checkin || !checkout || !roomType) return;
        if (!checkin.value || !checkout.value) return;
        let start = new Date(checkin.value);
        let end = new Date(checkout.value);
        let days = (end - start) / (1000 * 60 * 60 * 24);
        if (days <= 0) {
            totalPriceText.style.display = "none";
            return;
        }
        let total = prices[roomType.value] * days;
        totalPriceText.style.display = "block";
        priceValue.textContent = total.toLocaleString();
    }
    if (checkin) checkin.addEventListener("change", calculateTotal);
    if (checkout) checkout.addEventListener("change", calculateTotal);
    if (roomType) roomType.addEventListener("change", calculateTotal);

    window.addEventListener("scroll", () => {
        const footer = document.getElementById("footer");
        const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
        const windowHeight = window.innerHeight;
        const pageHeight = document.documentElement.scrollHeight;

        const atBottom = windowHeight + scrollTop >= pageHeight - 2;
        if (atBottom) {
            footer.classList.add("show");
        } else {
            footer.classList.remove("show");
        }
    });

});