
        const questions = {
             round1: [
                {
                    question: "Which of the following is the correct identifier?",
                    answers: ["$var_name", "VAR_123", "varname@", "None of the above"],
                    correct: "VAR_123"
                },
                {
                    question: "The programming language that has the ability to create new data types is called___.",
                    answers: ["Overloaded", "Encapsulated", "Reprehensible", "Extensible"],
                    correct: "Extensible"
                },
                {
                    question: "Which of the following is the original creator of the C++ language?",
                    answers: ["Dennis Ritchie", "Ken Thompson", "Bjarne Stroustrup", "Brian Kernighan"],
                    correct: "Bjarne Stroustrup"
                },
                {
                    question: "The C++ language is __ object-oriented language.",
                    answers: ["Pure Object oriented", "Not Object oriented", "Semi Object-oriented or Partial Object-oriented", "None of the above"],
                    correct: "Semi Object-oriented or Partial Object-oriented"
                },
                {
                    question: "Which type of memory is used by an Array in C++ programming language?",
                    answers: ["Contiguous", "None-contiguous", "Both A and B", "Not mentioned"],
                    correct: "Contiguous"
                },
                {
                    question: "What is the maximum possible length of an identifier?",
                    answers: ["16", "32", "64", "None of these above"],
                    correct: "None of these above"
                },
                {
                    question: "Which of these data types does Python not natively support?",
                    answers: ["Lists", "Tuples", "Arrays", "Dictionaries"],
                    correct: "Arrays"
                },
                {
                    question: "In which year was the Python 3.0 version developed?",
                    answers: ["2008", "2000", "2010", "2005"],
                    correct: "2008"
                },
                {
                    question: "What do we use to define a block of code in Python language?",
                    answers: ["Key", "Brackets", "Indentation", "None of these"],
                    correct: "Indentation"
                },
                {
                    question: "Which version of Python removed the print statement?",
                    answers: ["Python 1.x", "Python 2.x", "Python 3.x", "Python 4.x"],
                    correct: "Python 3.x"
                },
                {
                    question: "Which of the following is a mutable data type in Python?",
                    answers: ["String", "Tuple", "List", "Integer"],
                    correct: "List"
                },
                {
                    question: "Which of the following is not a Python built-in data type?",
                    answers: ["dict", "array", "set", "Frozenset"],
                    correct: "array"
                },
                {
                    question: "What does the sep parameter do in the print() function?",
                    answers: ["Separates lines", "Specifies separator between values", "Separates syntax errors", "None of these"],
                    correct: "Specifies separator between values"
                },
                {
                    question: "What happens if you try to access a non-existent key 'k' in a dictionary 'd' using d[k]?",
                    answers: ["Returns None", "Returns an empty string", "Raises a KeyError", "Creates a new key 'k' with value None"],
                    correct: "Raises a KeyError"
                },
                {
                    question: "How can you remove a key-value pair from a dictionary?",
                    answers: ["Using the del statement", "Using the remove() method", "Using the pop() method", "Both A and C"],
                    correct: "Both A and C"
                }
            ],
            round2: [
               {
                    question: "In Python, which keyword is used to check additional conditions if the previous conditions fail?",
                    answers: ["elif", "else if", "then", "switch"],
                    correct: "elif"
                },
                {
                    question: "What is the output of the following code? x = 10; if x > 5: print('Greater')",
                    answers: ["Error", "Greater", "Nothing", "Less"],
                    correct: "Greater"
                },
                {
                    question: "Which statement immediately terminates a loop in Python?",
                    answers: ["break", "continue", "exit", "stop"],
                    correct: "break"
                },
                {
                    question: "In a while loop, what happens if the condition never becomes False?",
                    answers: ["The loop runs forever", "The loop stops after 10 iterations", "Syntax error", "The loop doesn't start"],
                    correct: "The loop runs forever"
                },
                {
                    question: "What is the output of the following code? for i in range(3): print(i)",
                    answers: ["'0 1 2'", "'1 2 3'", "'0 1 2 3'", "Error"],
                    correct: "'0 1 2'"
                },
                {
                    question: "What is the main difference between a list and a tuple in Python?",
                    answers: ["Syntax", "Data type", "Mutability", "Method of declaration"],
                    correct: "Mutability"
                },
                {
                    question: "What is a dictionary in Python?",
                    answers: ["An ordered collection of elements", "A mutable collection of key-value pairs", "An immutable collection of items", "A collection of unique elements"],
                    correct: "A mutable collection of key-value pairs"
                },
                {
                    question: "What is an object in object-oriented programming?",
                    answers: ["A code snippet", "A variable", "An instance of a class", "A function"],
                    correct: "An instance of a class"
                },
                {
                    question: "Which of the following is a feature of procedure-oriented programming?",
                    answers: ["Class-based", "Focus on functions", "Inheritance", "Polymorphism"],
                    correct: "Focus on functions"
                },
                {
                    question: "In OOP, what does encapsulation refer to?",
                    answers: ["Storing data in arrays", "The process of inheritance", "Combining data and methods", "A type of loop"],
                    correct: "Combining data and methods"
                },
                {
                    question: "What is the output of the expression 5 + 3 * 2 in C++?",
                    answers: ["16", "11", "10", "8"],
                    correct: "11"
                },
                {
                    question: "What is the output of the following code? int a = 1; int b = 2; cout << (a++ + b);",
                    answers: ["3", "4", "Syntax error", "2"],
                    correct: "4"
                },
                {
                    question: "Find the mistake: int num; num == 5; cout << num;",
                    answers: ["Misuse of equality operator", "Undeclared variable", "No error", "Syntax error in cout statement"],
                    correct: "Misuse of equality operator"
                },
                {
                    question: "What is the purpose of default arguments in function definitions?",
                    answers: ["To specify what value a function returns", "To give a default value to a parameter if no argument is passed", "To make a parameter optional", "To overload a function"],
                    correct: "To give a default value to a parameter if no argument is passed"
                },
                {
                    question: "What are multidimensional arrays in C++?",
                    answers: ["Arrays with only one row or column", "Arrays with more than one dimension, like 2D or 3D arrays", "Arrays containing elements of different data types", "Dynamic arrays"],
                    correct: "Arrays with more than one dimension, like 2D or 3D arrays"
                }
            ],  
            round3: [
               {
                question: "What will be the output of the following Python code? i = 1 while True: if i%3 == 0: break print(i) i += 1",
                answers: ["1 2 3", "error", "1 2", "none of the mentioned"],
                correct: "1 2"
            },
            {
                question: "What are the values of the following Python expressions? 2*(32), (23)2, 23*2",
                answers: ["512, 64, 512", "512, 512, 512", "64, 512, 64", "64, 64, 64"],
                correct: "512, 64, 512"
            },
            {
                question: "Which of the following Python statements will result in the output: 6? A = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]",
                answers: ["A[2][1]", "A[1][2]", "A[3][2]", "A[2][3]"],
                correct: "A[1][2]"
            },
            {
                question: "What will be the output of the following Python program? i = 0 while i < 5: print(i) i += 1 if i == 3: break else: print(0)",
                answers: ["error", "0 1 2 0", "0 1 2", "none of the mentioned"],
                correct: "0 1 2"
            },
            {
                question: "What will be the output of the following Python code? x = 'abcd' for i in range(len(x)): print(i)",
                answers: ["error", "1 2 3 4", "a b c d", "0 1 2 3"],
                correct: "0 1 2 3"
            },
            {
                question: "What is the output of the below C++ program? #include <iostream> int main() { if(0) { std::cout << 'Hi'; } else { std::cout << 'Bye'; } return 0; }",
                answers: ["Hi", "Bye", "HiBye", "Compilation Error"],
                correct: "Bye"
            },
            {
                question: "What should be the output of the below C++ program? #include<iostream> int main() { int a=10; std::cout<<a++; return 0; }",
                answers: ["11", "10", "Error", "0"],
                correct: "10"
            },
            {
                question: "What is the output of the below C++ program? #include<iostream> int main() { const int a=10; a++; std::cout<<a; return 0; }",
                answers: ["10", "11", "Compilation Error", "Linking Error"],
                correct: "Compilation Error"
            },
            {
                question: "What is the value of a in the below C++ program? int main() { int a, b=20; a = 90/b; return 0; }",
                answers: ["4.5", "4.0", "4", "Compilation Error"],
                correct: "4"
            },
            {
                question: "What is the output of the below C++ program? int main() { int a=10; int b,c; b = a++; c = a; std::cout<<a<<b<<c; return 0; }",
                answers: ["111011", "111111", "101011", "101010"],
                correct: "101011"
            }
        ]
        };

        let currentRound = 1;
        let totalScore = 0;
        let userName = "";
        let userClass = "";
        let timeLeft = 900; // 15 minutes in seconds
        let timerInterval;

        function startQuiz() {
            userName = document.getElementById('name').value;
            userClass = document.getElementById('class').value;

            if (userName && userClass) {
                document.getElementById('userForm').style.display = 'none';
                document.getElementById('quizContent').style.display = 'block';
                document.getElementById('timer').style.display = 'block';
                loadQuestions();
                startTimer();
            } else {
                alert("Please enter your name and class.");
            }
        }

        function startTimer() {
            timerInterval = setInterval(function() {
                let minutes = Math.floor(timeLeft / 60);
                let seconds = timeLeft % 60;
                document.getElementById('timer').innerHTML = `Time Remaining: ${minutes}:${seconds < 10 ? '0' + seconds : seconds}`;
                timeLeft--;

                if (timeLeft < 0) {
                    clearInterval(timerInterval);
                    alert('Time is up!');
                    submitQuiz();
                }
            }, 1000);
        }

        function loadQuestions() {
            let questionsDiv = document.getElementById('questionsDiv');
            questionsDiv.innerHTML = '';
            let currentQuestions = questions[`round${currentRound}`];

            currentQuestions.forEach((q, index) => {
                let questionElement = document.createElement('div');
                questionElement.classList.add('question-container');
                questionElement.innerHTML =
                    `<label>${index + 1}. ${q.question}</label><br>
                    ${q.answers.map(answer => 
                        `<label><input type="radio" name="q${index}" value="${answer}">${answer}</label><br>`
                    ).join('')}`;
                questionsDiv.appendChild(questionElement);
            });
        }

        function submitQuiz() {
            clearInterval(timerInterval);

            let currentQuestions = questions[`round${currentRound}`];
            let roundScore = 0;

            currentQuestions.forEach((q, index) => {
                let selectedAnswer = document.querySelector(`input[name="q${index}"]:checked`);
                if (selectedAnswer && selectedAnswer.value === q.correct) {
                    roundScore++;
                }
            });

            totalScore += roundScore;
            showResults(roundScore);
        }

        function showResults(roundScore) {
            document.getElementById('quizContent').style.display = 'none';
            document.getElementById('resultContent').style.display = 'block';

            document.getElementById('userInfo').innerText = `Name: ${userName}, Class: ${userClass}`;
            document.getElementById('finalScore').innerText = `Score for Round ${currentRound}: ${roundScore}`;

            if (currentRound < 3) {
                document.getElementById('feedback').innerText = roundScore > 8
                    ? 'Congratulations! You are eligible for the next round.'
                    : 'Sorry, you did not qualify for the next round.';
                document.getElementById('feedback').classList.add(roundScore > 8 ? 'good' : 'bad');
                document.getElementById('nextRoundBtn').style.display = roundScore > 8 ? 'inline-block' : 'none';
            } else {
                document.getElementById('feedback').innerText = 'Thanks for the participation!';
                document.getElementById('feedback').classList.add('good');
                document.getElementById('nextRoundBtn').style.display = 'none';
            }
        }

        function nextRound() {
            currentRound++;
            if (currentRound <= 3) {
                document.getElementById('resultContent').style.display = 'none';
                document.getElementById('quizContent').style.display = 'block';
                timeLeft = 900; // Reset timer
                loadQuestions();
                startTimer();
            }
        }

        document.getElementById('startQuizBtn').addEventListener('click', startQuiz);
        document.getElementById('submitBtn').addEventListener('click', submitQuiz);
        document.getElementById('nextRoundBtn').addEventListener('click', nextRound);
        document.addEventListener('contextmenu', function (e) {
    e.preventDefault();
    alert("Right-click is disabled on this page!");
});
   // Add an event listener for beforeunload
window.addEventListener('beforeunload', function (event) {
    // Customize the message shown in modern browsers
    event.preventDefault(); // Some browsers require this for the message to show
    event.returnValue = ''; // Setting this displays the default confirmation dialog
});
// Disable text selection
document.addEventListener('selectstart', function (e) {
    e.preventDefault();
    alert("Text selection is disabled.");
  });
  
  // Disable specific keyboard shortcuts
  document.addEventListener('keydown', function (e) {
    // Disable Ctrl+C, Ctrl+X, Ctrl+S, Ctrl+U
    if (e.ctrlKey && ['c', 'x', 's', 'u'].includes(e.key.toLowerCase())) {
      e.preventDefault();
      alert("Keyboard shortcuts are disabled.");
    }
  });

