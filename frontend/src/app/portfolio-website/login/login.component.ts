import { CommonModule } from '@angular/common';
import { Component } from '@angular/core';
import { FormBuilder, ReactiveFormsModule, Validators } from '@angular/forms';
import { Router } from '@angular/router';
import { MatSnackBar } from '@angular/material/snack-bar';
import { AuthService } from '../auth.service';
import { HttpClientModule } from '@angular/common/http';
import { Observable } from 'rxjs';

@Component({
  selector: 'app-login',
  standalone: true,
  imports: [ReactiveFormsModule, CommonModule, HttpClientModule],
  templateUrl: './login.component.html',
  styleUrls: ['./login.component.scss'], // Fixed styleUrls
  providers: [AuthService]
})
export class LoginComponent {
  errorMessage: string = '';
  loginForm = this.fb.group({
    email: ['', [Validators.required, Validators.email]],
    password: ['', Validators.required]
  });

  registerForm = this.fb.group({
    firstName: ['', Validators.required],
    lastName: ['', Validators.required],
    dob: ['', Validators.required],
    gender: ['', Validators.required],
    address: ['', Validators.required],
    email: ['', [Validators.required, Validators.email]],
    mobile: ['', [Validators.required, Validators.pattern(/^[0-9]{10}$/)]],
    country: ['', Validators.required],
    password: ['', [Validators.required, Validators.minLength(6)]],
    confirmPassword: ['', Validators.required]
  });

  activeForm: 'login' | 'register' = 'login';

  constructor(
    private fb: FormBuilder,
    private router: Router,
    private snackBar: MatSnackBar,
    private authService: AuthService,
  ) { }

  toggleForm(form: 'login' | 'register') {
    this.activeForm = form;
  }

  login() {
    if (this.loginForm.valid) {
      console.log("Login info==>", this.loginForm.value);

      // Use type assertion to ensure proper type
      const credentials = this.loginForm.value as { email: string; password: string };

      this.authService.login(credentials).subscribe({
        next: (response: any) => {
          console.log("Login successful", response);
          this.router.navigate(['/portfolio-website/home']);
        },
        error: (error: any) => {
          console.error("Login failed", error);
          this.snackBar.open("Invalid email or Password!", 'close', { duration: 3000 });
        }
      });
    } else {
      this.snackBar.open("Invalid email or Password!", 'close', { duration: 3000 });
    }
  }


  register() {
    if (this.registerForm.valid) {
      if (this.registerForm.value.password === this.registerForm.value.confirmPassword) {
        console.log("Register Form Data", this.registerForm.value);

        this.authService.register(this.registerForm.value).subscribe({
          next: (response: any) => {
            console.log("Registration successful", response);
            this.router.navigate(['/login']);
            this.snackBar.open('Registration successful!', 'Close', { duration: 3000 });
          },
          error: (error: any) => {
            console.error("Registration failed", error);
            this.snackBar.open('Registration failed!', 'Close', { duration: 3000 });
          }
        });
      } else {
        this.snackBar.open('Passwords do not match!', 'Close', { duration: 3000 });
      }
    } else {
      this.snackBar.open('Please fill in all fields correctly!', 'Close', { duration: 3000 });
    }
  }


  

}





