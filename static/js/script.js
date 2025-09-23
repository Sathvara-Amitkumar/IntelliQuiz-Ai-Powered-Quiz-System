// static/js/script.js
document.addEventListener('DOMContentLoaded', function() {
    // --- Signup Page: Show/Hide Password & Confirm Password ---
    const passwordInput = document.getElementById('password');
    const confirmPasswordInput = document.getElementById('confirm_password');
    const togglePasswordBtn = document.getElementById('toggle-password');
    const toggleConfirmPasswordBtn = document.getElementById('toggle-confirm-password');
    if (passwordInput && togglePasswordBtn) {
        togglePasswordBtn.addEventListener('click', function() {
            const isPassword = passwordInput.type === 'password';
            passwordInput.type = isPassword ? 'text' : 'password';
            togglePasswordBtn.textContent = isPassword ? 'Hide' : 'Show';
        });
    }
    if (confirmPasswordInput && toggleConfirmPasswordBtn) {
        toggleConfirmPasswordBtn.addEventListener('click', function() {
            const isPassword = confirmPasswordInput.type === 'password';
            confirmPasswordInput.type = isPassword ? 'text' : 'password';
            toggleConfirmPasswordBtn.textContent = isPassword ? 'Hide' : 'Show';
        });
    }
    const signupForm = document.querySelector('form[action*="signup"]');
    if (signupForm && passwordInput && confirmPasswordInput) {
        signupForm.addEventListener('submit', function(e) {
            if (passwordInput.value !== confirmPasswordInput.value) {
                e.preventDefault();
                alert('Passwords do not match.');
                confirmPasswordInput.focus();
            }
        });
    }

    // --- Student Dashboard: Join Quiz ---
    const joinQuizForm = document.getElementById('join-quiz-form');
    if (joinQuizForm) {
        joinQuizForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            let roomCode = document.getElementById('room_code').value.trim().toUpperCase();
            const errorDiv = document.getElementById('join-error');
            try {
                const response = await fetch('/student/api/quiz/join', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ room_code: roomCode })
                });
                const result = await response.json();
                if (response.ok && result.success) {
                    window.location.href = `/student/quiz/${result.quiz_id}`;
                } else if (response.redirected) {
                    // In case server decided to redirect (non-JSON flow)
                    window.location.href = response.url;
                } else {
                    errorDiv.textContent = result.error || 'Failed to join quiz.';
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = error.message || 'Network error. Please try again.';
                errorDiv.style.display = 'block';
            }
        });

        // Auto-join if room_code provided via URL (e.g., ?room_code=ABC123)
        const params = new URLSearchParams(window.location.search);
        const urlRoom = params.get('room_code');
        if (urlRoom) {
            const input = document.getElementById('room_code');
            input.value = urlRoom.toUpperCase();
            // Trigger the same submission flow
            joinQuizForm.requestSubmit();
        }
    }

    // --- Teacher: Quiz Details Page ---
    const deleteQuizBtn = document.getElementById('delete-quiz-btn');
    if (deleteQuizBtn) {
        deleteQuizBtn.addEventListener('click', async function() {
            const quizId = deleteQuizBtn.dataset.quizId;
            if (confirm('Are you sure you want to delete this quiz and all its results? This action cannot be undone.')) {
                try {
                    const response = await fetch(`/teacher/api/quiz/delete/${quizId}`, {
                        method: 'POST',
                        credentials: 'same-origin'
                    });
                    const result = await response.json();
                    if (response.ok) {
                        window.location.href = '/teacher/dashboard';
                    } else {
                        throw new Error(result.error);
                    }
                } catch (error) {
                    alert('Error deleting quiz: ' + error.message);
                }
            }
        });
    }

    // --- Student: Quiz Taker Page ---
    const quizForm = document.getElementById('quiz-form');
    if (quizForm && window.quizConfig && Array.isArray(window.quizConfig.questionsData) && typeof window.quizConfig.antiCheatingFeatures === 'object') {
        const antiCheatingFeatures = window.quizConfig.antiCheatingFeatures;
        let questionsData = window.quizConfig.questionsData;
        let currentQuestionIndex = 0;
        let studentAnswers = new Array(questionsData.length).fill(null);
        let timeLeft;
        let timerInterval;
        let tabSwitchCount = 0;
        let rapidChangeCount = 0;
        let lastChangeTime = Date.now();
        const AUTO_SUBMIT_REASON = { NONE: '', TAB: 'tab_switch', RAPID: 'rapid_change', FULLSCREEN: 'fullscreen_exit' };
        let autoSubmitReason = AUTO_SUBMIT_REASON.NONE;

        function doAutoSubmit(reason) {
            if (!antiCheatingFeatures.auto_submit) return;
            autoSubmitReason = reason || AUTO_SUBMIT_REASON.NONE;
            try { quizForm.requestSubmit(); } catch (_) { quizForm.submit(); }
        }

        // Copy/paste prevention
        if (antiCheatingFeatures.copy_paste_prevention) {
            document.addEventListener('contextmenu', function(e) {
                if (quizForm.contains(e.target)) e.preventDefault();
            });
            quizForm.addEventListener('copy', function(e) { e.preventDefault(); });
            quizForm.addEventListener('paste', function(e) { e.preventDefault(); });
            quizForm.addEventListener('cut', function(e) { e.preventDefault(); });
        }
        // Tab switch detection
        if (antiCheatingFeatures.tab_switch_detection) {
            window.addEventListener('blur', function() {
                tabSwitchCount++;
                alert('Warning: You switched away from the quiz window. This is logged.');
                fetch('/student/api/log_suspicious', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ event: 'tab_switch', quiz_id: quizForm.dataset.quizId })
                });
                if (tabSwitchCount > 3) doAutoSubmit(AUTO_SUBMIT_REASON.TAB);
            });
        }
        // Fullscreen required
        if (antiCheatingFeatures.fullscreen_mode) {
            function ensureFullscreen() {
                if (!document.fullscreenElement && quizForm.requestFullscreen) {
                    quizForm.requestFullscreen().catch(function(){
                        // If cannot enter fullscreen, warn and optionally auto-submit
                        alert('This quiz requires fullscreen. Please allow fullscreen to continue.');
                        doAutoSubmit(AUTO_SUBMIT_REASON.FULLSCREEN);
                    });
                }
            }
            ensureFullscreen();
            document.addEventListener('fullscreenchange', function(){
                if (!document.fullscreenElement) {
                    alert('You exited fullscreen. This action is logged.');
                    if (antiCheatingFeatures.auto_submit) doAutoSubmit(AUTO_SUBMIT_REASON.FULLSCREEN);
                }
            });
        }
        if (antiCheatingFeatures.random_question_order) {
            questionsData = [...questionsData].sort(function() { return Math.random() - 0.5; });
        }
        // Helper function to shuffle options
        function shuffleOptions(question) {
            const options = question.options.slice();
            const shuffledOptions = options.map(function(opt, i) {
                return { option: opt, originalIndex: i };
            }).sort(function() { return Math.random() - 0.5; });
            question.options = shuffledOptions.map(function(item) { return item.option; });
            question.optionMapping = shuffledOptions.map(function(item) { return item.originalIndex; });
            return question;
        }
        // Lock quiz after submit
        quizForm.addEventListener('submit', function() {
            Array.prototype.forEach.call(quizForm.elements, function(el) { el.disabled = true; });
        });
        // Timer logic
        const timerElement = document.getElementById('timer');
        const timeLimitMinutes = parseInt(quizForm.dataset.timeLimit, 10);
        timeLeft = timeLimitMinutes * 60;
        timerInterval = setInterval(function() {
            if (timeLeft <= 0) {
                clearInterval(timerInterval);
                timerElement.textContent = "Time's Up!";
                quizForm.requestSubmit();
                return;
            }
            timeLeft--;
            if (timeLeft < 60 && !timerElement.classList.contains('low-time')) {
                timerElement.classList.add('low-time');
            }
            const minutes = Math.floor(timeLeft / 60);
            const seconds = timeLeft % 60;
            timerElement.textContent = (minutes < 10 ? '0' : '') + minutes + ':' + (seconds < 10 ? '0' : '') + seconds;
        }, 1000);
        // Quiz navigation and rendering
        const questionContainer = document.getElementById('question-container');
        const prevBtn = document.getElementById('prev-btn');
        const nextBtn = document.getElementById('next-btn');
        const submitBtn = document.getElementById('submit-btn');
        const progressText = document.getElementById('question-progress');
        const progressBar = document.getElementById('progress-bar-inner');
        function renderQuestion() {
            const question = questionsData[currentQuestionIndex];
            if (antiCheatingFeatures.random_option_order && !question.optionMapping) {
                shuffleOptions(question);
            }
            let optionsHTML = '<div class="space-y-4">';
            question.options.forEach(function(option, index) {
                const mappedIndex = question.optionMapping ? question.optionMapping[index] : index;
                const isSelected = studentAnswers[currentQuestionIndex] === mappedIndex;
                optionsHTML += '<button type="button" class="option-btn' + (isSelected ? ' selected' : '') + '" data-option-index="' + mappedIndex + '"><span><strong>' + String.fromCharCode(65 + index) + '.</strong> ' + option + '</span></button>';
            });
            optionsHTML += '</div>';
            questionContainer.innerHTML = '<h2 style="font-size: 1.5rem; font-weight: 600; margin-bottom: 2rem;">' + question.question_text + '</h2>' + optionsHTML;
            progressText.textContent = 'Question ' + (currentQuestionIndex + 1) + ' of ' + questionsData.length;
            progressBar.style.width = (((currentQuestionIndex + 1) / questionsData.length) * 100) + '%';
            prevBtn.disabled = currentQuestionIndex === 0;
            nextBtn.style.display = currentQuestionIndex === questionsData.length - 1 ? 'none' : 'inline-flex';
            submitBtn.style.display = currentQuestionIndex === questionsData.length - 1 ? 'inline-flex' : 'none';
        }
        questionContainer.addEventListener('click', function(e) {
            const target = e.target.closest('.option-btn');
            if (target) {
                const now = Date.now();
                if (antiCheatingFeatures.speed_monitoring && (now - lastChangeTime) < 500) {
                    rapidChangeCount++;
                    fetch('/student/api/log_suspicious', {
                        method: 'POST',
                        credentials: 'same-origin',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ event: 'rapid_change', quiz_id: quizForm.dataset.quizId })
                    });
                    if (rapidChangeCount > 10) doAutoSubmit(AUTO_SUBMIT_REASON.RAPID);
                }
                lastChangeTime = now;
                const selectedIndex = parseInt(target.dataset.optionIndex, 10);
                studentAnswers[currentQuestionIndex] = selectedIndex;
                renderQuestion();
            }
        });
        prevBtn.addEventListener('click', function() {
            if (currentQuestionIndex > 0) {
                currentQuestionIndex--;
                renderQuestion();
            }
        });
        nextBtn.addEventListener('click', function() {
            if (currentQuestionIndex < questionsData.length - 1) {
                currentQuestionIndex++;
                renderQuestion();
            }
        });
        quizForm.addEventListener('submit', async function(e) {
            e.preventDefault();
            if (antiCheatingFeatures.strict_time_limits && timeLeft <= 0) {
                alert("Time's up! Your answers will be submitted automatically.");
            }
            const quizId = quizForm.dataset.quizId;
            const answersPayload = {};
            questionsData.forEach(function(q, index) {
                if (studentAnswers[index] !== null) {
                    const answer = q.optionMapping ? q.optionMapping.indexOf(studentAnswers[index]) : studentAnswers[index];
                    answersPayload[q.id] = answer;
                }
            });
            const speedData = {};
            if (antiCheatingFeatures.speed_monitoring) {
                speedData.completionTime = timeLimitMinutes * 60 - timeLeft;
                speedData.averageTimePerQuestion = speedData.completionTime / questionsData.length;
                speedData.rapidChanges = rapidChangeCount;
            }
            try {
                const response = await fetch('/student/api/quiz/submit', {
                    method: 'POST',
                    credentials: 'same-origin',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ quiz_id: quizId, answers: answersPayload, speed_data: speedData, auto_submit_reason: autoSubmitReason })
                });
                const result = await response.json();
                if (response.ok) {
                    window.location.href = '/student/quiz/result/' + result.result_id;
                } else {
                    throw new Error(result.error);
                }
            } catch (error) {
                alert('Error submitting quiz: ' + error.message);
            }
        });
        renderQuestion();

        // Show error if no questions or flash message
        if (!Array.isArray(questionsData) || questionsData.length === 0) {
            document.getElementById('quiz-error-message').textContent = 'This quiz has no questions. Please contact your teacher.';
            document.getElementById('quiz-error-message').style.display = 'block';
            quizForm.style.display = 'none';
        }
        if (window.quizConfig.flashMessage) {
            document.getElementById('quiz-error-message').textContent = window.quizConfig.flashMessage;
            document.getElementById('quiz-error-message').style.display = 'block';
            quizForm.style.display = 'none';
        }
    }

    // --- Student: Quiz Result Page ---
    const progressCircle = document.getElementById('progress-circle');
    if (progressCircle && typeof resultData !== 'undefined') {
        const percentage = resultData.total_questions > 0 ? (resultData.score / resultData.total_questions) * 100 : 0;
        const progressText = document.getElementById('progress-text');
        const feedbackMessage = document.getElementById('feedback-message');
        const radius = 45;
        const circumference = 2 * Math.PI * radius;
        const offset = circumference - (percentage / 100) * circumference;
        setTimeout(function() {
            progressCircle.style.strokeDashoffset = offset;
            let currentPercent = 0;
            const interval = setInterval(function() {
                if (currentPercent >= Math.round(percentage)) {
                    clearInterval(interval);
                    progressText.textContent = Math.round(percentage) + '%';
                } else {
                    currentPercent++;
                    progressText.textContent = currentPercent + '%';
                }
            }, 20);
        }, 100);
        let feedback = { message: "Keep Practicing!", color: "var(--red-700)" };
        if (percentage >= 90) feedback = { message: "Excellent!", color: "var(--green-600)" };
        else if (percentage >= 75) feedback = { message: "Great Job!", color: "var(--primary-600)" };
        else if (percentage >= 50) feedback = { message: "Good Effort!", color: "var(--accent-500)" };
    }
});

